// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Server-side request-framing hardening (HTTP/WS family hardening Group 3). These
// tests drive a REAL HttpServer over a raw socket so they exercise the framing
// layer (HttpServer::handleData / findChunkedRequestEnd) — NOT just the parser
// (HttpRequest::fromWireFormat), which the parser-level tests already cover.
//   - SRV-H1: a chunked request body (incl. a trailer-section) is de-chunked and
//     the handler receives the decoded body.
//   - Anti-smuggling: an ambiguous-framing request (Content-Length+Transfer-
//     Encoding, conflicting duplicate Content-Length, non-final chunked coding,
//     obs-fold / whitespace-before-colon on a framing header, malformed chunk
//     framing, invalid Content-Length) is answered 400 and the connection is
//     POISONED — trailing bytes are NOT dispatched as a smuggled request.
//   - Regression: legitimate keep-alive pipelining of well-formed requests still
//     dispatches every request.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/http_server.hpp"
#include "iora_test_net_utils.hpp" // uses Catch2 REQUIRE -> must follow catch.hpp

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>

using iora::network::HttpServer;

namespace
{
/// \brief Minimal raw HTTP/1.1 client that can send arbitrary crafted bytes and
/// read one response head + Content-Length body (and detect a subsequent close).
class Conn
{
public:
  bool open(int port)
  {
    _fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (_fd < 0)
    {
      return false;
    }
    timeval tv{};
    tv.tv_sec = 4;
    ::setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    return ::connect(_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
  }

  ~Conn()
  {
    if (_fd >= 0)
    {
      ::close(_fd);
    }
  }

  void sendRaw(const std::string &bytes)
  {
    std::size_t off = 0;
    while (off < bytes.size())
    {
      ssize_t n = ::send(_fd, bytes.data() + off, bytes.size() - off, 0);
      if (n <= 0)
      {
        break;
      }
      off += static_cast<std::size_t>(n);
    }
  }

  /// \brief Read the first response's status code and body (Content-Length or
  /// read-to-close). Returns {status, body}; status 0 on no/short response
  /// (also the signal that the peer closed with nothing more to send).
  std::pair<int, std::string> readResponse()
  {
    std::string buf;
    std::size_t hdrEnd;
    while ((hdrEnd = buf.find("\r\n\r\n")) == std::string::npos)
    {
      if (!fill(buf))
      {
        return {0, ""};
      }
    }
    const std::string head = buf.substr(0, hdrEnd);
    buf.erase(0, hdrEnd + 4);

    int status = 0;
    {
      const std::size_t lineEnd = head.find("\r\n");
      std::string statusLine = (lineEnd == std::string::npos) ? head : head.substr(0, lineEnd);
      std::istringstream ss(statusLine);
      std::string ver;
      ss >> ver >> status;
    }

    std::size_t clPos = head.find("Content-Length:");
    if (clPos == std::string::npos)
    {
      clPos = head.find("content-length:");
    }
    if (clPos != std::string::npos)
    {
      const std::size_t valStart = head.find(':', clPos) + 1;
      const std::size_t valEnd = head.find("\r\n", valStart);
      std::string clStr = head.substr(valStart, valEnd - valStart);
      clStr.erase(0, clStr.find_first_not_of(" \t"));
      const std::size_t len = static_cast<std::size_t>(std::stoul(clStr));
      while (buf.size() < len)
      {
        if (!fill(buf))
        {
          break;
        }
      }
      return {status, buf.substr(0, std::min(len, buf.size()))};
    }
    while (fill(buf))
    {
    }
    return {status, buf};
  }

private:
  bool fill(std::string &buf)
  {
    char tmp[4096];
    ssize_t n = ::recv(_fd, tmp, sizeof(tmp), 0);
    if (n <= 0)
    {
      return false;
    }
    buf.append(tmp, static_cast<std::size_t>(n));
    return true;
  }

  int _fd = -1;
};

/// \brief Spin until pred() or timeout; returns pred()'s final value.
template <typename Pred> bool waitFor(Pred pred, int maxMs)
{
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(maxMs);
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (pred())
    {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  return pred();
}

/// \brief Assert that `crafted` (an ambiguous/malformed-framing request stream
/// with a trailing GET /admin) is answered 400 and the smuggled /admin handler
/// NEVER runs — i.e. the framer poisons the connection instead of framing and
/// dispatching the trailing bytes. When checkClosed, also assert the connection
/// is closed after the 400 (a second read returns nothing).
void expectPoisonNoSmuggle(const std::string &crafted, bool checkClosed = false)
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<int> adminCount{0};
  // Lead request targets POST /first (framed but poisoned, never dispatched); the
  // smuggled trailer targets GET /admin. No case issues GET /first.
  srv.onPost("/first", [](const HttpServer::Request &, HttpServer::Response &res)
             { res.set_content("first", "text/plain"); });
  srv.onGet("/admin", [&adminCount](const HttpServer::Request &, HttpServer::Response &res)
            {
              adminCount.fetch_add(1);
              res.set_content("admin", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  c.sendRaw(crafted);
  auto [status, body] = c.readResponse();
  (void)body;
  REQUIRE(status == 400);
  // If the trailing request were framed+dispatched, adminCount would tick within
  // this window. It must stay 0.
  REQUIRE_FALSE(waitFor([&adminCount]() { return adminCount.load() > 0; }, 500));
  REQUIRE(adminCount.load() == 0);
  if (checkClosed)
  {
    auto [status2, body2] = c.readResponse();
    (void)body2;
    REQUIRE(status2 == 0); // connection closed after the poison 400
  }
}
} // namespace

TEST_CASE("HttpServer de-chunks a request body with a trailer-section (SRV-H1)",
          "[http_server][framing][chunked]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<int> echoCount{0};
  srv.onPost("/echo",
             [&echoCount](const HttpServer::Request &req, HttpServer::Response &res)
             {
               echoCount.fetch_add(1);
               res.set_content(req.body, "text/plain");
             });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  // Two chunks + a trailer field-line + the closing empty line.
  c.sendRaw("POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "5\r\nHello\r\n6\r\n World\r\n0\r\nX-Trailer: v\r\n\r\n");
  auto [status, body] = c.readResponse();
  REQUIRE(status == 200);
  REQUIRE(body == "Hello World"); // decoded, trailer stripped
  REQUIRE(echoCount.load() == 1);
}

TEST_CASE("HttpServer poisons the connection on Content-Length+Transfer-Encoding (no smuggle)",
          "[http_server][framing][smuggling]")
{
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
}

TEST_CASE("HttpServer poisons the connection on conflicting duplicate Content-Length (no smuggle)",
          "[http_server][framing][smuggling]")
{
  // "0" and "00" are DIFFERENT tokens (conflicting duplicate CL -> poison) but
  // BOTH parse to length 0, so a regressed framer (poison removed -> single-CL
  // path) would deterministically frame an empty body and then dispatch the
  // trailing GET /admin. This makes adminCount==0 a real discriminator, not a
  // vacuous assertion that passes because the parser 400s dup-CL independently.
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        "Content-Length: 0\r\nContent-Length: 00\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
}

TEST_CASE("HttpServer rejects a Transfer-Encoding whose final coding is not chunked (SRV-H2)",
          "[http_server][framing][smuggling]")
{
  // Last Transfer-Encoding line is gzip (not chunked-final). A regressed framer
  // that OR'd "chunked" over all TE lines would chunk-frame the body, dispatch
  // /first, then dispatch the trailing GET /admin.
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n"
                        "5\r\nHello\r\n0\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
}

TEST_CASE("HttpServer poisons on an obs-folded framing header (no smuggle)",
          "[http_server][framing][smuggling]")
{
  // Obs-fold: " Content-Length: 0" is a continuation of X-Foo per RFC 9112 §5.2
  // (which a server MUST reject). A regressed framer that trimmed the leading
  // whitespace would HONOR Content-Length: 0, frame an empty body, and dispatch
  // the trailing GET /admin. Also assert the connection closes after the 400.
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Foo: bar\r\n"
                        " Content-Length: 0\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                        /*checkClosed=*/true);
}

TEST_CASE("HttpServer poisons on whitespace before a header colon (no smuggle)",
          "[http_server][framing][smuggling]")
{
  // "Content-Length : 0" — whitespace before the colon (RFC 9112 §5.1, MUST
  // reject). A regressed framer that trimmed it would honor CL:0 and smuggle.
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length : 0\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
}

TEST_CASE("HttpServer answers 400 (does not stall) on a malformed chunk-size (SRV-H2)",
          "[http_server][framing][chunked]")
{
  // Non-HEXDIG chunk-size on a COMPLETE line: the parser 400s this, so the framer
  // must too (a definitively-malformed body), rather than treat it as "need more
  // data" and stall (a stall would return status 0 at the socket timeout).
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                        "zz\r\nx\r\n0\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
}

TEST_CASE("HttpServer answers 400 on a chunk-data run not terminated by CRLF",
          "[http_server][framing][chunked]")
{
  // "5\r\nHelloXX..." — 5 bytes "Hello" then "XX" instead of the required CRLF.
  // The framer must not scan past the bad terminator (which would frame a bogus
  // boundary and could smuggle); it answers 400 and poisons.
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                        "5\r\nHelloXX0\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
}

TEST_CASE("HttpServer poisons on an obs-folded chunked trailer field-line (no smuggle)",
          "[http_server][framing][chunked]")
{
  // The decoder rejects an obs-folded trailer (SP/HTAB-led) 400; the framer must
  // too — otherwise it accepts the trailer, frames the POST, and (framing/dispatch
  // being decoupled) dispatches the trailing GET /admin before the POST's 400
  // closes the connection. Guards R5-1: header-vs-trailer obs-fold parity.
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                        "5\r\nHello\r\n0\r\n\tX-Fold: v\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
}

TEST_CASE("HttpServer answers 400 (not a bare close) on an invalid single Content-Length",
          "[http_server][framing]")
{
  // NEW-M1: the framer validates the single Content-Length (1*DIGIT) BEFORE
  // dispatch and emits 400+close, rather than the old silent bare close. A
  // trailing GET /admin must not be dispatched.
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: abc\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                        /*checkClosed=*/true);
}

TEST_CASE("HttpServer answers 400 on an out-of-range (>2^64) Content-Length",
          "[http_server][framing]")
{
  // 1*DIGIT but numerically unrepresentable -> unframeable -> 400 (not bare close).
  expectPoisonNoSmuggle("POST /first HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        "Content-Length: 99999999999999999999\r\n\r\n"
                        "GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
}

TEST_CASE("HttpServer still pipelines well-formed keep-alive requests (regression)",
          "[http_server][framing]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<int> aCount{0};
  std::atomic<int> bCount{0};
  srv.onGet("/a", [&aCount](const HttpServer::Request &, HttpServer::Response &res)
            {
              aCount.fetch_add(1);
              res.set_content("a", "text/plain");
            });
  srv.onGet("/b", [&bCount](const HttpServer::Request &, HttpServer::Response &res)
            {
              bCount.fetch_add(1);
              res.set_content("b", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  // Two well-formed pipelined requests on one connection: both handlers must run
  // (the ambiguous-framing poison must not fire on legitimate pipelining).
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
            "GET /b HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
  (void)c.readResponse();
  REQUIRE(waitFor([&]() { return aCount.load() >= 1 && bCount.load() >= 1; }, 1000));
}
