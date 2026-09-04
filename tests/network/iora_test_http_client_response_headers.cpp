// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// HttpClient response-header + request-body framing hardening (tracker
// 2026-07-26-10 task-1.7 b/c/d/e). parseHeaderBlock folded duplicate response
// field-lines last-wins, so "Content-Encoding: gzip" then "identity" presented
// as identity — defeating any client-side coding check (defect_8). The fix
// COMBINES list-valued duplicates (Content-Encoding / Accept-Encoding) into an
// ordered comma-list via the shared iora::parsers::detail::addOrCombineHeader,
// keeps the singleton conflicting-Content-Length throw independent, REJECTS a
// duplicate Transfer-Encoding response field-line (defect_18), and documents the
// OWS-before-colon leniency (defect_10). Separately, executeRequest now emits
// Content-Length: 0 for an empty body on a content-anticipating method
// (POST/PUT/PATCH, defect_13). A raw mock server controls the exact response
// bytes. Catch2 macros run on the MAIN thread only. Run under ASan
// (handle_segv=0); ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include "network/http_client_test_server.hpp"
#include <iora/parsers/json.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
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

std::string readHeaderBlock(int cs)
{
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
  return acc;
}

using RawHandler = std::function<void(int)>;

class RawServer
{
public:
  bool start(std::uint16_t port, RawHandler handler)
  {
    _listenFd = makeListener(port);
    if (_listenFd < 0)
    {
      return false;
    }
    _handler = std::move(handler);
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
      if (cs >= 0)
      {
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 400 * 1000;
        ::setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        _handler(cs);
        ::close(cs);
        return; // one-shot
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }

  int _listenFd{-1};
  std::thread _thread;
  std::atomic<bool> _stop{false};
  RawHandler _handler;
};

// Reply with a fixed raw response after draining the request header block.
RawHandler once(std::string response)
{
  return [response](int cs)
  {
    readHeaderBlock(cs);
    writeAll(cs, response);
  };
}

// Record the request header block into *out, then reply 200. The caller MUST
// join the server (shutdown) before reading *out, which establishes the
// happens-before for the read.
RawHandler recordRequest(std::shared_ptr<std::string> out)
{
  return [out](int cs)
  {
    *out = readHeaderBlock(cs);
    writeAll(cs, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
  };
}

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

// ── defect_8: duplicate Content-Encoding COMBINES into an ordered comma-list ──
TEST_CASE("response: duplicate Content-Encoding combines in arrival order",
          "[http][response][defect_8]")
{
  const std::uint16_t port = 19310;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
                               "Content-Encoding: identity\r\nContent-Length: 2\r\n\r\nhi")));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  HttpClient client(cfg());
  auto r = client.get(urlFor(port));
  REQUIRE(r.statusCode == 200);
  // Combined "gzip, identity" — NOT last-wins "identity", NOT a throw.
  auto it = r.headers.find("Content-Encoding");
  REQUIRE(it != r.headers.end());
  CHECK(it->second == "gzip, identity");
  raw.shutdown();
}

// ── defect_8 MUST-DO: a CONFLICTING duplicate Content-Length still throws ──────
TEST_CASE("response: conflicting duplicate Content-Length still throws",
          "[http][response][defect_8]")
{
  const std::uint16_t port = 19311;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                               "Content-Length: 7\r\n\r\nhello")));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  HttpClient client(cfg());
  CHECK_THROWS_AS(client.get(urlFor(port)), iora::network::HttpFramingError);
  raw.shutdown();
}

// An IDENTICAL duplicate Content-Length is not a conflict (RFC 9112 §6.3 rule 5):
// it must NOT throw, proving the combine change did not turn CL into a list.
TEST_CASE("response: identical duplicate Content-Length is accepted",
          "[http][response][defect_8]")
{
  const std::uint16_t port = 19312;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                               "Content-Length: 2\r\n\r\nhi")));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  HttpClient client(cfg());
  auto r = client.get(urlFor(port));
  REQUIRE(r.statusCode == 200);
  CHECK(r.body == "hi");
  CHECK(r.headers.find("Content-Length")->second == "2"); // not "2, 2"
  raw.shutdown();
}

// ── defect_18: a duplicate Transfer-Encoding response field-line is REJECTED ──
TEST_CASE("response: two Transfer-Encoding field-lines throw a framing error",
          "[http][response][defect_18]")
{
  const std::uint16_t port = 19313;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                               "Transfer-Encoding: gzip\r\n\r\n0\r\n\r\n")));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  HttpClient client(cfg());
  CHECK_THROWS_AS(client.get(urlFor(port)), iora::network::HttpFramingError);
  raw.shutdown();
}

// Even IDENTICAL duplicate TE lines are rejected (RFC 9112 §6.1: chunked must not
// be applied more than once) — the asymmetry with Content-Length is intentional.
TEST_CASE("response: identical duplicate Transfer-Encoding lines throw",
          "[http][response][defect_18]")
{
  const std::uint16_t port = 19314;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                               "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  HttpClient client(cfg());
  CHECK_THROWS_AS(client.get(urlFor(port)), iora::network::HttpFramingError);
  raw.shutdown();
}

// A SINGLE Transfer-Encoding line with an internal comma-list ("gzip, chunked")
// is unaffected: chunked is the final coding, so the body de-chunks as before.
TEST_CASE("response: a single comma-list Transfer-Encoding line frames normally",
          "[http][response][defect_18]")
{
  const std::uint16_t port = 19315;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n"
                               "\r\n2\r\nhi\r\n0\r\n\r\n")));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  HttpClient client(cfg());
  auto r = client.get(urlFor(port));
  REQUIRE(r.statusCode == 200);
  CHECK(r.body == "hi");
  raw.shutdown();
}

// ── defect_10: OWS before the colon is accepted (documented leniency) ─────────
TEST_CASE("response: whitespace before the colon is accepted and the name trimmed",
          "[http][response][defect_10]")
{
  const std::uint16_t port = 19316;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nX-Foo : bar\r\nContent-Length: 2\r\n\r\nhi")));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));
  HttpClient client(cfg());
  auto r = client.get(urlFor(port));
  REQUIRE(r.statusCode == 200);
  // The trailing OWS is stripped from the name; the field is stored as "X-Foo".
  auto it = r.headers.find("X-Foo");
  REQUIRE(it != r.headers.end());
  CHECK(it->second == "bar");
  raw.shutdown();
}

// ── defect_13: an empty-body POST carries Content-Length: 0; a GET carries none ─
TEST_CASE("request: empty-body POST emits Content-Length: 0, GET emits none",
          "[http][request][defect_13]")
{
  {
    const std::uint16_t port = 19317;
    auto captured = std::make_shared<std::string>();
    RawServer raw;
    REQUIRE(raw.start(port, recordRequest(captured)));
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    HttpClient client(cfg());
    auto r = client.post(urlFor(port), "");
    REQUIRE(r.statusCode == 200);
    raw.shutdown(); // join before reading *captured
    CHECK(captured->find("Content-Length: 0\r\n") != std::string::npos);
  }
  {
    const std::uint16_t port = 19318;
    auto captured = std::make_shared<std::string>();
    RawServer raw;
    REQUIRE(raw.start(port, recordRequest(captured)));
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 200);
    raw.shutdown();
    // A body-less GET does not anticipate content — no Content-Length line.
    CHECK(captured->find("Content-Length:") == std::string::npos);
  }
}
