// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// HttpClient scheme-qualified connection cache key (tracker 2026-07-26-10
// task-1.9 / defect_12). acquireConnection keyed _connections / _leasedHosts on
// host:port with NO scheme, so an https:// request following an http:// request
// to the same host:port reused the PLAINTEXT session — a silent TLS downgrade.
// ParsedUrl::getHostPort() now returns scheme://host:port, so the two are
// distinct keys and an https request never reuses a plaintext connection.
//
// TEST STRATEGY (no TLS cert needed): a PLAINTEXT keep-alive server. After an
// http:// request caches a plaintext connection, an https:// request to the SAME
// host:port must open a FRESH connection (distinct key) and perform a real TLS
// handshake — which FAILS against the plaintext peer, so the request THROWS.
// MUTATION: revert getHostPort() to host:port and the https request instead
// REUSES the plaintext session and returns 200 (the downgrade) — so the throw is
// exactly the fix's signature. The server handles each connection on its own
// thread so a kept-alive http connection does not block accepting the https one.
// Catch2 macros run on the MAIN thread only. Run under TSan (setarch -R) + ASan
// (handle_segv=0); ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include "network/http_client_test_server.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace iora::network;

namespace
{
using iora::test::httpsrv::makeListener;

/// \brief Multi-connection plaintext keep-alive server: one worker thread per
/// accepted connection, each looping request->200 until the peer closes. So a
/// kept-alive connection never blocks accepting another (needed to model an
/// http and an https connection to the same authority at once).
class MultiServer
{
public:
  bool start(std::uint16_t port)
  {
    _listenFd = makeListener(port);
    if (_listenFd < 0)
    {
      return false;
    }
    _accept = std::thread([this] { run(); });
    return true;
  }

  ~MultiServer() { shutdown(); }

  void shutdown()
  {
    if (!_stop.exchange(true))
    {
      if (_accept.joinable())
      {
        _accept.join();
      }
      std::lock_guard<std::mutex> lk(_m);
      for (auto &t : _workers)
      {
        if (t.joinable())
        {
          t.join();
        }
      }
      _workers.clear();
      if (_listenFd >= 0)
      {
        ::close(_listenFd);
        _listenFd = -1;
      }
    }
  }

private:
  void run()
  {
    while (!_stop.load())
    {
      sockaddr_in ca{};
      socklen_t cl = sizeof(ca);
      int cs = ::accept(_listenFd, reinterpret_cast<sockaddr *>(&ca), &cl);
      if (cs < 0)
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        continue;
      }
      std::lock_guard<std::mutex> lk(_m);
      _workers.emplace_back([this, cs] { serve(cs); });
    }
  }

  void serve(int cs)
  {
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 200 * 1000;
    ::setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    // Keep-alive response (no Connection: close) so the client caches the socket.
    static const std::string kResp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    while (!_stop.load())
    {
      std::string acc;
      char buf[2048];
      bool gotReq = false;
      for (int i = 0; i < 20 && !_stop.load(); ++i)
      {
        ssize_t n = ::recv(cs, buf, sizeof(buf), 0);
        if (n > 0)
        {
          acc.append(buf, static_cast<std::size_t>(n));
          if (acc.find("\r\n\r\n") != std::string::npos)
          {
            gotReq = true;
            break;
          }
        }
        else if (n == 0)
        {
          ::close(cs); // peer closed
          return;
        }
        else
        {
          break; // recv timeout: no request this round
        }
      }
      if (!gotReq)
      {
        continue;
      }
      std::size_t off = 0;
      while (off < kResp.size())
      {
        ssize_t n = ::send(cs, kResp.data() + off, kResp.size() - off, MSG_NOSIGNAL);
        if (n <= 0)
        {
          ::close(cs);
          return;
        }
        off += static_cast<std::size_t>(n);
      }
    }
    ::close(cs);
  }

  int _listenFd{-1};
  std::thread _accept;
  std::atomic<bool> _stop{false};
  std::mutex _m;
  std::vector<std::thread> _workers;
};

HttpClient::Config cfg()
{
  HttpClient::Config c;
  c.requestTimeout = std::chrono::milliseconds(2000);
  c.connectTimeout = std::chrono::milliseconds(1000);
  c.reuseConnections = true; // caching is required for the downgrade to be possible
  return c;
}

void configureTls(HttpClient &client)
{
  HttpClient::TlsConfig tlsCfg;
  tlsCfg.verifyPeer = false; // we never reach verification: the handshake itself fails
  client.setTlsConfig(tlsCfg);
}

} // namespace

// http:// then https:// to the SAME host:port: the https request must NOT reuse
// the cached plaintext connection. With the scheme-qualified key it opens a
// fresh connection and its TLS handshake fails against the plaintext server, so
// it THROWS. With the old host:port key it would reuse the plaintext session and
// return 200 — the downgrade. The throw is the fix's signature.
TEST_CASE("https does not reuse a plaintext connection to the same host:port",
          "[http][scheme_key][defect_12]")
{
  const std::uint16_t port = 19350;
  MultiServer server;
  REQUIRE(server.start(port));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  HttpClient client(cfg());
  configureTls(client);
  const std::string base = "127.0.0.1:" + std::to_string(port) + "/x";

  auto httpResp = client.get("http://" + base);
  REQUIRE(httpResp.statusCode == 200); // plaintext connection now cached

  // The https request opens a NEW connection (distinct key) -> real TLS
  // handshake against a plaintext peer -> failure -> throw. NOT a 200.
  CHECK_THROWS(client.get("https://" + base));

  server.shutdown();
}

// The failed https attempt must not evict or corrupt the cached http entry: a
// second http request still succeeds (distinct keys, no cross-evict).
TEST_CASE("a failed https attempt does not evict the http cache entry",
          "[http][scheme_key][defect_12]")
{
  const std::uint16_t port = 19351;
  MultiServer server;
  REQUIRE(server.start(port));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  HttpClient client(cfg());
  configureTls(client);
  const std::string base = "127.0.0.1:" + std::to_string(port) + "/x";

  REQUIRE(client.get("http://" + base).statusCode == 200);
  CHECK_THROWS(client.get("https://" + base));
  // http still works — the http entry was independent of the https key.
  CHECK(client.get("http://" + base).statusCode == 200);

  server.shutdown();
}

// Concurrency (thread-safety M-2): the scheme-qualified key NEWLY enables an
// http and an https request to the same authority to run in parallel (they held
// one shared lease before). Distinct keys must mean no shared cache slot, no
// cross-evict, no double-close. Run repeatedly; the http side always succeeds,
// the https side always throws, and nothing crashes/deadlocks. Meaningful under
// TSan (setarch -R): it exercises concurrent _mutex-guarded map access on two
// keys for one authority.
TEST_CASE("concurrent http + https to one authority is race-free",
          "[http][scheme_key][defect_12][tsan]")
{
  const std::uint16_t port = 19352;
  MultiServer server;
  REQUIRE(server.start(port));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  HttpClient client(cfg());
  configureTls(client);
  const std::string base = "127.0.0.1:" + std::to_string(port) + "/x";

  // Start-barrier: both threads spin until released so they hit acquireConnection
  // as simultaneously as the scheduler allows (thread-safety L-1 — the prior
  // version had a nondeterministic overlap window). 20 iterations widens the
  // interleaving search vs. the original 5.
  for (int iter = 0; iter < 20; ++iter)
  {
    std::atomic<int> httpOk{0};
    std::atomic<int> httpsThrew{0};
    std::atomic<bool> go{false};
    std::thread th([&]
                   {
                     while (!go.load(std::memory_order_acquire)) {}
                     try
                     {
                       if (client.get("http://" + base).statusCode == 200)
                       {
                         httpOk.fetch_add(1);
                       }
                     }
                     catch (...) {}
                   });
    std::thread ts([&]
                   {
                     while (!go.load(std::memory_order_acquire)) {}
                     try
                     {
                       client.get("https://" + base);
                     }
                     catch (...)
                     {
                       httpsThrew.fetch_add(1);
                     }
                   });
    go.store(true, std::memory_order_release);
    th.join();
    ts.join();
    CHECK(httpOk.load() == 1);
    CHECK(httpsThrew.load() == 1);
  }

  server.shutdown();
}

// SYMMETRIC direction (task-1.9 verification, cpp17 L1): the tracker names an
// "https then http also opens a fresh connection" case. It is NOT tested with a
// discriminating assertion here BY DESIGN: the fix is the single scheme-qualified
// getHostPort() key, so http://h:p and https://h:p are distinct keys REGARDLESS
// of which is issued first — the two directions are equivalent by construction,
// not by a runtime ordering. A plaintext-only harness also cannot discriminate
// the symmetric case (an https-first request never establishes a session to
// reuse). The structural single-key re-key is what makes the symmetric direction
// redundant to test; the http->https case above already exercises the key
// separation. (Recorded per the code-review integrity rule rather than left
// silent.)
