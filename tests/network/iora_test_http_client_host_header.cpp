// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// RFC 9110 §7.2 / RFC 9112 §3.2 Host field emission for HttpClient (tracker
// 2026-07-26-10 task-1.7(a) / defect_11): a request to a non-default port MUST
// carry `Host: host:port`, not a port-less `Host: host` (which broke name-based
// vhosts and gateways). A raw-socket mock server captures the exact request
// header bytes so the emitted Host line is asserted at the wire, not inferred.
// Catch2 macros run on the MAIN thread only; the server records under a mutex.
// Run under ASan (handle_segv=0); ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace iora::network;

namespace
{

int makeListener(std::uint16_t port)
{
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    return -1;
  }
  int opt = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");
  addr.sin_port = htons(port);
  if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
  {
    ::close(fd);
    return -1;
  }
  if (::listen(fd, 16) < 0)
  {
    ::close(fd);
    return -1;
  }
  int flags = ::fcntl(fd, F_GETFL, 0);
  ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  return fd;
}

/// \brief A one-shot raw server that captures the first request's header block
/// (up to CRLFCRLF) and replies 200 OK, so a test can assert the exact Host line.
class CapturingServer
{
public:
  bool start(std::uint16_t port)
  {
    _listenFd = makeListener(port);
    if (_listenFd < 0)
    {
      return false;
    }
    _thread = std::thread([this] { run(); });
    return true;
  }

  ~CapturingServer() { shutdown(); }

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

  /// \brief The captured request header block. The reliable happens-before is
  /// shutdown()'s join; read this only after shutdown().
  std::string capturedRequest() const
  {
    std::lock_guard<std::mutex> lk(_m);
    return _request;
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

      std::string acc;
      char buf[2048];
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
      {
        std::lock_guard<std::mutex> lk(_m);
        _request = acc;
      }
      static const std::string kResp =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
      std::size_t off = 0;
      while (off < kResp.size())
      {
        ssize_t n = ::send(cs, kResp.data() + off, kResp.size() - off, MSG_NOSIGNAL);
        if (n <= 0)
        {
          break;
        }
        off += static_cast<std::size_t>(n);
      }
      ::close(cs);
      return; // one-shot
    }
  }

  int _listenFd{-1};
  std::thread _thread;
  std::atomic<bool> _stop{false};
  mutable std::mutex _m;
  std::string _request;
};

/// \brief Count the field lines in a captured header block whose name (before the
/// first ':') equals `name` (ASCII, case-sensitive on the emitted canonical form).
std::size_t countHeaderLines(const std::string &req, const std::string &name)
{
  std::size_t n = 0;
  std::size_t pos = req.find("\r\n"); // skip the request line
  const std::string prefix = name + ":";
  while (pos != std::string::npos)
  {
    const std::size_t lineStart = pos + 2;
    const std::size_t lineEnd = req.find("\r\n", lineStart);
    if (lineEnd == std::string::npos || lineEnd == lineStart)
    {
      break; // end of headers
    }
    if (req.compare(lineStart, prefix.size(), prefix) == 0)
    {
      ++n;
    }
    pos = lineEnd;
  }
  return n;
}

HttpClient::Config cfg()
{
  HttpClient::Config c;
  c.requestTimeout = std::chrono::milliseconds(2000);
  c.connectTimeout = std::chrono::milliseconds(1000);
  c.reuseConnections = false;
  return c;
}

} // namespace

// task-1.7(a) / defect_11 — the pure Host-line formatter, unit-tested for all
// branches WITHOUT a socket (the default-port branch cannot be exercised end-to-
// end because it would require binding privileged port 80/443).
TEST_CASE("formatHostHeaderField omits the default port and keeps a non-default one",
          "[http][host][defect_11]")
{
  using iora::network::formatHostHeaderField;
  // http default (80) omitted; https default (443) omitted.
  CHECK(formatHostHeaderField("example.com", 80, false) == "Host: example.com\r\n");
  CHECK(formatHostHeaderField("example.com", 443, true) == "Host: example.com\r\n");
  // Non-default ports carried, for both schemes.
  CHECK(formatHostHeaderField("example.com", 8080, false) == "Host: example.com:8080\r\n");
  CHECK(formatHostHeaderField("example.com", 8443, true) == "Host: example.com:8443\r\n");
  // A port equal to the OTHER scheme's default is still non-default and is
  // carried: 443 is not http's default (80), and 80 is not https's default (443).
  CHECK(formatHostHeaderField("h", 443, false) == "Host: h:443\r\n");
  CHECK(formatHostHeaderField("h", 80, true) == "Host: h:80\r\n");
}

// task-1.7(a) / defect_11 — a request to a NON-DEFAULT port carries the port in
// the Host line. This is the exact wire outcome tracker -2 task-7.3a gates on.
// Mutation-test: reverting the emitter to `parsedUrl.host` alone drops the ":port"
// and fails the exact-match assertion.
TEST_CASE("HttpClient emits Host with the port for a non-default port",
          "[http][host][defect_11]")
{
  const std::uint16_t port = 18190;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/rpc";
  auto resp = client.get(url);
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());

  const std::string expected = "Host: 127.0.0.1:" + std::to_string(port) + "\r\n";
  CHECK(req.find(expected) != std::string::npos);
  // Exactly one Host line, and it is NOT the port-less form.
  CHECK(countHeaderLines(req, "Host") == 1);
  CHECK(req.find("Host: 127.0.0.1\r\n") == std::string::npos);
}

// A second distinct non-default port, to guard against a hard-coded port value.
TEST_CASE("HttpClient Host port tracks the URL port", "[http][host][defect_11]")
{
  const std::uint16_t port = 18191;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  auto resp = client.get("http://127.0.0.1:" + std::to_string(port) + "/x");
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  CHECK(req.find("Host: 127.0.0.1:18191\r\n") != std::string::npos);
  CHECK(req.find(":18190") == std::string::npos);
}
