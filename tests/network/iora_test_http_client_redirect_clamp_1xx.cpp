// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// HttpClient task-1.8 (tracker 2026-07-26-10): the dead redirect config
// (defect_5), the loopback connect-timeout clamp (defect_9), and the 1xx
// citation (defect_16). followRedirects/maxRedirects are reserved-and-inert —
// HttpClient follows no redirects — so the default no longer advertises the
// capability (followRedirects defaults false). The interim-1xx skip path
// (documented RFC 9110 §15.2) must frame the final response after discarding a
// 100-continue. The loopback clamp is a DOCUMENTED behavior (Config::connectTimeout
// + the clamp site); it is not directly assertable here. A raw mock server
// controls the exact response bytes. Catch2 macros run on the MAIN thread only.
// Run under ASan (handle_segv=0); ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include "network/http_client_test_server.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace iora::network;

namespace
{
using iora::test::httpsrv::makeListener;
using iora::test::httpsrv::writeAll;

class RawServer
{
public:
  bool start(std::uint16_t port, std::string response)
  {
    _response = std::move(response);
    _listenFd = makeListener(port);
    if (_listenFd < 0)
    {
      return false;
    }
    _thread = std::thread([this] { run(); });
    return true;
  }

  ~RawServer() { shutdown(); }

  void shutdown()
  {
    if (!_stop.exchange(true))
    {
      if (_thread.joinable())
      {
        _thread.join();
      }
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
      timeval tv{};
      tv.tv_sec = 0;
      tv.tv_usec = 400 * 1000;
      ::setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      char buf[2048];
      std::string acc;
      for (int i = 0; i < 100 && acc.find("\r\n\r\n") == std::string::npos; ++i)
      {
        ssize_t n = ::recv(cs, buf, sizeof(buf), 0);
        if (n > 0)
        {
          acc.append(buf, static_cast<std::size_t>(n));
        }
        else
        {
          break;
        }
      }
      writeAll(cs, _response);
      ::close(cs);
      return;
    }
  }

  int _listenFd{-1};
  std::thread _thread;
  std::atomic<bool> _stop{false};
  std::string _response;
};

HttpClient::Config cfg()
{
  HttpClient::Config c;
  c.requestTimeout = std::chrono::milliseconds(2000);
  c.connectTimeout = std::chrono::milliseconds(1000);
  c.reuseConnections = false;
  return c;
}

std::string urlFor(std::uint16_t port) { return "http://127.0.0.1:" + std::to_string(port) + "/x"; }

} // namespace

// defect_5: the reserved-and-inert redirect config no longer advertises a
// capability the client lacks — followRedirects defaults FALSE.
TEST_CASE("Config does not advertise redirect-following it never performs",
          "[http][redirect][defect_5]")
{
  HttpClient::Config c;
  CHECK(c.followRedirects == false);
}

// defect_16 / DD-12: an interim 100-continue is skipped and the following 200 is
// framed correctly. Locks the behavior the corrected RFC 9110 §15.2 comment
// describes.
TEST_CASE("An interim 1xx is discarded and the final 200 is framed",
          "[http][1xx][defect_16]")
{
  const std::uint16_t port = 19330;
  RawServer raw;
  REQUIRE(raw.start(port, "HTTP/1.1 100 Continue\r\n\r\n"
                          "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  HttpClient client(cfg());
  auto r = client.get(urlFor(port));
  CHECK(r.statusCode == 200);
  CHECK(r.body == "hi");
  raw.shutdown();
}

// Two interim 1xx responses before the final one are both skipped.
TEST_CASE("Multiple interim 1xx responses are all discarded", "[http][1xx][defect_16]")
{
  const std::uint16_t port = 19331;
  RawServer raw;
  REQUIRE(raw.start(port, "HTTP/1.1 100 Continue\r\n\r\n"
                          "HTTP/1.1 103 Early Hints\r\n\r\n"
                          "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nyay"));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  HttpClient client(cfg());
  auto r = client.get(urlFor(port));
  CHECK(r.statusCode == 200);
  CHECK(r.body == "yay");
  raw.shutdown();
}
