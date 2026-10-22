// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// HttpClient applies Config::connectTimeout to loopback connects (tracker
// 2026-08-02-1, HD-2). Row A: a loopback connect that takes longer than 200 ms
// completes. Row B: a loopback connect that never completes fails at
// connectTimeout. The measured GET runs on a detached thread that owns its
// state; Catch2 macros run on the MAIN thread only; ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include "iora_test_net_utils.hpp"
#include "tcp_connect_test_fixtures.hpp"

#include <linux/sock_diag.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <fstream>
#include <future>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using iora::network::HttpClient;
using iora::network::HttpConnectTimeoutError;

namespace {

struct Outcome
{
  int status{-1};
  bool connectTimeout{false};
  std::string error;
  std::chrono::milliseconds elapsed{0};
};

struct GetState
{
  std::promise<Outcome> done;
  std::atomic<bool> started{false};
};

std::shared_ptr<HttpClient> makeWarmClient(std::chrono::milliseconds connectTimeout)
{
  HttpClient::Config cfg;
  cfg.connectTimeout = connectTimeout;
  cfg.requestTimeout = 3000ms;
  cfg.reuseConnections = false;
  auto client = std::make_shared<HttpClient>(cfg);
  testnet::RefusingEndpoint refusing;
  try
  {
    client->get("http://127.0.0.1:" + std::to_string(refusing.port()) + "/");
  }
  catch (...)
  {
  }
  return client;
}

std::future<Outcome> startGet(const std::shared_ptr<HttpClient> &client, const std::string &url,
                              const std::shared_ptr<GetState> &state)
{
  auto fut = state->done.get_future();
  std::thread(
    [client = client, url, state]() mutable
    {
      Outcome o;
      const auto t0 = std::chrono::steady_clock::now();
      state->started.store(true);
      try
      {
        o.status = client->get(url).statusCode;
      }
      catch (const HttpConnectTimeoutError &e)
      {
        o.connectTimeout = true;
        o.error = e.what();
      }
      catch (const std::exception &e)
      {
        o.error = e.what();
      }
      catch (...)
      {
        o.error = "unknown exception";
      }
      o.elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
      client.reset();
      state->done.set_value(o);
    })
    .detach();
  return fut;
}

std::int64_t listenerDrops(int fd)
{
  std::uint32_t mem[SK_MEMINFO_VARS] = {};
  socklen_t len = sizeof(mem);
  if (::getsockopt(fd, SOL_SOCKET, SO_MEMINFO, mem, &len) != 0)
  {
    return -1;
  }
  return mem[SK_MEMINFO_DROPS];
}

std::int64_t netstatListenDrops()
{
  std::ifstream in("/proc/net/netstat");
  std::string header;
  std::string values;
  while (std::getline(in, header) && std::getline(in, values))
  {
    if (header.rfind("TcpExt:", 0) != 0)
    {
      continue;
    }
    std::istringstream hs(header);
    std::istringstream vs(values);
    std::string name;
    std::string value;
    while (hs >> name && vs >> value)
    {
      if (name == "ListenDrops")
      {
        return std::stoll(value);
      }
    }
  }
  return -1;
}

std::uint16_t localPort(int fd)
{
  sockaddr_storage ss{};
  socklen_t sl = sizeof(ss);
  if (::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &sl) != 0)
  {
    return 0;
  }
  return ntohs(reinterpret_cast<sockaddr_in *>(&ss)->sin_port);
}

std::uint16_t peerPort(int fd)
{
  sockaddr_storage ss{};
  socklen_t sl = sizeof(ss);
  if (::getpeername(fd, reinterpret_cast<sockaddr *>(&ss), &sl) != 0)
  {
    return 0;
  }
  return ntohs(reinterpret_cast<sockaddr_in *>(&ss)->sin_port);
}

bool readRequestHead(int fd, std::chrono::milliseconds bound)
{
  std::string buf;
  const auto deadline = std::chrono::steady_clock::now() + bound;
  while (buf.find("\r\n\r\n") == std::string::npos)
  {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0)
    {
      return false;
    }
    pollfd p{fd, POLLIN, 0};
    if (::poll(&p, 1, static_cast<int>(left.count())) != 1)
    {
      return false;
    }
    char chunk[1024];
    const ssize_t n = ::recv(fd, chunk, sizeof(chunk), 0);
    if (n <= 0)
    {
      return false;
    }
    buf.append(chunk, static_cast<std::size_t>(n));
  }
  return true;
}

struct ThreadJoiner
{
  std::thread &t;
  ~ThreadJoiner()
  {
    if (t.joinable())
    {
      t.join();
    }
  }
};

} // namespace

TEST_CASE("HttpClient loopback connect slower than 200 ms completes", "[http_client][loopback_connect]")
{
  const auto connectTimeout = 6000ms;
  auto client = makeWarmClient(connectTimeout);

  tcptest::Blackhole bh;
  REQUIRE(bh.fill());
  std::set<std::uint16_t> fillerPorts;
  for (int f : bh.fillers)
  {
    fillerPorts.insert(localPort(f));
  }
  const std::int64_t dropsBase = listenerDrops(bh.lst.fd);
  const std::int64_t netstatBase = netstatListenDrops();
  REQUIRE(dropsBase >= 0);

  auto state = std::make_shared<GetState>();
  std::atomic<bool> listenerDropSeen{false};
  std::atomic<bool> netstatDropSeen{false};
  std::atomic<int> fillersAccepted{0};
  std::atomic<int> clientPeerPort{0};
  std::atomic<bool> requestRead{false};
  std::atomic<bool> responseWritten{false};

  std::thread helper(
    [&]
    {
      (void)tcptest::waitFor([&] { return state->started.load(); }, 2000ms);
      const auto dropBound = std::chrono::steady_clock::now() + 2000ms;
      while (std::chrono::steady_clock::now() < dropBound)
      {
        if (listenerDrops(bh.lst.fd) > dropsBase)
        {
          listenerDropSeen.store(true);
          break;
        }
        if (netstatBase >= 0 && netstatListenDrops() > netstatBase)
        {
          netstatDropSeen.store(true);
        }
        std::this_thread::sleep_for(1ms);
      }
      if (!listenerDropSeen.load() && !netstatDropSeen.load())
      {
        return;
      }
      for (std::size_t i = 0; i < bh.fillers.size(); ++i)
      {
        const int a = tcptest::acceptWithin(bh.lst.fd, 1000ms);
        if (a < 0)
        {
          return;
        }
        ::close(a);
        fillersAccepted.fetch_add(1);
      }
      const int peer = tcptest::acceptWithin(bh.lst.fd, connectTimeout + 1000ms);
      if (peer < 0)
      {
        return;
      }
      clientPeerPort.store(peerPort(peer));
      if (readRequestHead(peer, 3000ms))
      {
        requestRead.store(true);
        static const char kResponse[] = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        responseWritten.store(::send(peer, kResponse, sizeof(kResponse) - 1, MSG_NOSIGNAL) ==
                              static_cast<ssize_t>(sizeof(kResponse) - 1));
        std::this_thread::sleep_for(200ms);
      }
      ::close(peer);
    });
  ThreadJoiner joinHelper{helper};

  auto fut = startGet(client, "http://127.0.0.1:" + std::to_string(bh.lst.port) + "/", state);
  REQUIRE(fut.wait_for(connectTimeout + 10000ms) == std::future_status::ready);
  const Outcome o = fut.get();
  helper.join();

  INFO("status=" << o.status << " error=" << o.error << " elapsed_ms=" << o.elapsed.count()
                 << " listenerDrop=" << listenerDropSeen.load()
                 << " netstatDrop=" << netstatDropSeen.load());
  REQUIRE((listenerDropSeen.load() || netstatDropSeen.load()));
  REQUIRE(fillersAccepted.load() == static_cast<int>(bh.fillers.size()));
  REQUIRE(clientPeerPort.load() != 0);
  REQUIRE(fillerPorts.count(static_cast<std::uint16_t>(clientPeerPort.load())) == 0);
  REQUIRE(requestRead.load());
  REQUIRE(responseWritten.load());
  REQUIRE(o.status == 200);
  REQUIRE(o.elapsed >= 900ms);
}

TEST_CASE("HttpClient loopback connect that never completes fails at connectTimeout",
          "[http_client][loopback_connect]")
{
  const auto connectTimeout = 600ms;
  auto client = makeWarmClient(connectTimeout);

  tcptest::Blackhole bh;
  REQUIRE(bh.fill());

  auto state = std::make_shared<GetState>();
  auto fut = startGet(client, "http://127.0.0.1:" + std::to_string(bh.lst.port) + "/", state);
  REQUIRE(fut.wait_for(10000ms) == std::future_status::ready);
  const Outcome o = fut.get();

  INFO("status=" << o.status << " error=" << o.error << " elapsed_ms=" << o.elapsed.count());
  REQUIRE(o.connectTimeout);
  REQUIRE(o.elapsed >= 550ms);
  REQUIRE(o.elapsed < 1600ms);
}
