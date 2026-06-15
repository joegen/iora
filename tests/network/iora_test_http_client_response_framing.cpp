// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// RFC 9112 §6.3 / §7.1 response message-body framing for HttpClient: close-delimited
// bodies, no-body statuses (HEAD/204/304/1xx), proper chunked parsing (no substring
// completeness), numeric overflow guards, receive cap, CL-vs-TE reject, obs-fold
// reject, multi-1xx skip. Tracker: 2026-06-14-6 (design_decisions v2.2).
//
// NOTE: a CONNECT-tunnel response (RFC 9112 §6.3 rule 2) is a declared NON-GOAL —
// HttpClient never issues CONNECT, so that defensive reject path is not exercised here.
//
// A raw-socket mock server controls the EXACT response bytes (WebhookServer rewrites
// framing headers, so it cannot emit these cases). Catch2 macros run on the MAIN
// thread only; the server runs on its own thread and records to atomics. Run under
// TSan (setarch -R) + ASan (handle_segv=0); ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <functional>
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
  addr.sin_addr.s_addr = INADDR_ANY;
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

void writeAll(int fd, const std::string &data)
{
  std::size_t off = 0;
  while (off < data.size())
  {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n <= 0)
    {
      break;
    }
    off += static_cast<std::size_t>(n);
  }
}

// Read one request's headers (clientSock has a recv timeout). Returns true if a full
// header block arrived; false on timeout/close (lets a keep-alive handler loop).
bool readRequest(int clientSock)
{
  char buf[2048];
  std::string acc;
  for (int i = 0; i < 100; ++i)
  {
    ssize_t n = ::recv(clientSock, buf, sizeof(buf), 0);
    if (n > 0)
    {
      acc.append(buf, static_cast<std::size_t>(n));
      if (acc.find("\r\n\r\n") != std::string::npos)
      {
        return true;
      }
    }
    else
    {
      return false;
    }
  }
  return false;
}

/// \brief Per-connection handler given the accepted socket (does its own read/write).
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

  int acceptedCount() const { return _accepted.load(); }

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
        _accepted.fetch_add(1);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 400 * 1000;
        ::setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        _handler(cs);
        ::close(cs);
      }
      else
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
    }
  }

  int _listenFd{-1};
  std::thread _thread;
  std::atomic<bool> _stop{false};
  std::atomic<int> _accepted{0};
  RawHandler _handler;
};

// Single-shot: read the request, write the response, then RawServer closes the socket.
RawHandler once(std::string response)
{
  return [response](int cs)
  {
    readRequest(cs);
    writeAll(cs, response);
  };
}

// Keep-alive: serve the same response for each request on one persistent socket.
RawHandler keepAlive(std::string response)
{
  return [response](int cs)
  {
    while (readRequest(cs))
    {
      writeAll(cs, response);
    }
  };
}

HttpClient::Config cfg()
{
  HttpClient::Config c;
  c.requestTimeout = std::chrono::milliseconds(2000);
  c.connectTimeout = std::chrono::milliseconds(1000);
  return c;
}

std::string urlFor(std::uint16_t port) { return "http://127.0.0.1:" + std::to_string(port) + "/x"; }

} // namespace

// ── (a) close-delimited body (no CL/TE) fully received on PeerClosed ──────────
TEST_CASE("framing: close-delimited body received on connection close", "[http_framing][close]")
{
  const std::uint16_t port = 19000;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\n\r\nHELLO-CLOSE-DELIMITED-BODY")));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  auto r = client.get(urlFor(port));
  REQUIRE(r.statusCode == 200);
  REQUIRE(r.body == "HELLO-CLOSE-DELIMITED-BODY");
  raw.shutdown();
}

// ── (b) chunk data containing "0\r\n\r\n"/embedded CRLF not truncated; reuse OK ─
TEST_CASE("framing: chunked body with embedded terminator sequence not truncated",
          "[http_framing][chunked]")
{
  const std::uint16_t port = 19001;
  // body "abc0\r\n\r\ndef" is 11 octets (0x0b); the bytes "0\r\n\r\n" appear INSIDE it.
  const std::string resp =
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\nabc0\r\n\r\ndef\r\n0\r\n\r\n";
  RawServer raw;
  REQUIRE(raw.start(port, keepAlive(resp)));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  auto r1 = client.get(urlFor(port));
  REQUIRE(r1.statusCode == 200);
  REQUIRE(r1.body == "abc0\r\n\r\ndef");
  // Second request on the SAME kept-alive connection must not desync.
  auto r2 = client.get(urlFor(port));
  REQUIRE(r2.body == "abc0\r\n\r\ndef");
  REQUIRE(raw.acceptedCount() == 1);
  raw.shutdown();
}

// ── (c)/(c+) chunk-ext (quoted-string), leading zeros, BWS around ';' and '=' ──
TEST_CASE("framing: chunked with chunk-ext, leading zeros and BWS decodes",
          "[http_framing][chunked][ext]")
{
  const std::uint16_t port = 19002;
  // "05" leading zero; chunk-ext "; name = \"v;al\"" with BWS around ';' and '='.
  const std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                           "05 ; name = \"v;al\"\r\nHELLO\r\n0\r\n\r\n";
  RawServer raw;
  REQUIRE(raw.start(port, once(resp)));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  auto r = client.get(urlFor(port));
  REQUIRE(r.statusCode == 200);
  REQUIRE(r.body == "HELLO");
  raw.shutdown();
}

// ── (d) chunked with a non-empty trailer-section consumed; reuse OK ───────────
TEST_CASE("framing: chunked trailer-section consumed without desync", "[http_framing][chunked][trailer]")
{
  const std::uint16_t port = 19003;
  const std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                           "5\r\nHELLO\r\n0\r\nX-Trace: abc\r\nX-More: 1\r\n\r\n";
  RawServer raw;
  REQUIRE(raw.start(port, keepAlive(resp)));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  REQUIRE(client.get(urlFor(port)).body == "HELLO");
  REQUIRE(client.get(urlFor(port)).body == "HELLO"); // no desync from unconsumed trailer
  REQUIRE(raw.acceptedCount() == 1);
  raw.shutdown();
}

// ── (e) HEAD with Content-Length returns immediately, empty body ──────────────
TEST_CASE("framing: HEAD response with Content-Length has no body", "[http_framing][nobody][head]")
{
  const std::uint16_t port = 19004;
  RawServer raw;
  REQUIRE(raw.start(port, keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  auto r = client.head(urlFor(port));
  REQUIRE(r.statusCode == 200);
  REQUIRE(r.body.empty()); // must NOT wait for the 100 phantom body bytes
  raw.shutdown();
}

// ── (f) 204 and 304 have no body ──────────────────────────────────────────────
TEST_CASE("framing: 204 and 304 have no body", "[http_framing][nobody]")
{
  SECTION("204 No Content")
  {
    const std::uint16_t port = 19005;
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 204 No Content\r\n\r\n")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 204);
    REQUIRE(r.body.empty());
    raw.shutdown();
  }
  SECTION("304 Not Modified with a phantom Content-Length")
  {
    const std::uint16_t port = 19006;
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\n\r\n")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 304);
    REQUIRE(r.body.empty());
    raw.shutdown();
  }
}

// ── (g) cap: oversized body (mid-receipt) and up-front Content-Length > cap ────
TEST_CASE("framing: response cap is enforced", "[http_framing][cap]")
{
  SECTION("close-delimited body exceeding the cap is rejected mid-receipt")
  {
    const std::uint16_t port = 19007;
    RawServer raw;
    REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\n\r\n" + std::string(20000, 'X'))));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient::Config c = cfg();
    c.maxResponseBytes = 4096;
    c.jsonConfig.maxPayloadSize = 1024; // effectiveCap = max(4096,1024) = 4096
    HttpClient client(c);
    REQUIRE_THROWS_AS(client.get(urlFor(port)), HttpFramingError);
    raw.shutdown();
  }
  SECTION("Content-Length exceeding the cap is rejected up front")
  {
    const std::uint16_t port = 19008;
    RawServer raw;
    REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient::Config c = cfg();
    c.maxResponseBytes = 4096;
    c.jsonConfig.maxPayloadSize = 1024;
    HttpClient client(c);
    REQUIRE_THROWS_AS(client.get(urlFor(port)), HttpFramingError);
    raw.shutdown();
  }
  SECTION("oversized header block (no terminator) is rejected")
  {
    const std::uint16_t port = 19009;
    RawServer raw;
    REQUIRE(raw.start(port, once(std::string(20000, 'X')))); // never a \r\n\r\n
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient::Config c = cfg();
    c.maxResponseBytes = 4096;
    c.jsonConfig.maxPayloadSize = 1024;
    HttpClient client(c);
    REQUIRE_THROWS_AS(client.get(urlFor(port)), HttpFramingError);
    raw.shutdown();
  }
}

// ── (h)/(h+) malformed numerics and lenient-LF/bare-CR are framing errors ─────
TEST_CASE("framing: malformed framing fields throw HttpFramingError (no UB)", "[http_framing][malformed]")
{
  auto expectFramingThrow = [](std::uint16_t port, const std::string &resp)
  {
    RawServer raw;
    REQUIRE(raw.start(port, once(resp)));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE_THROWS_AS(client.get(urlFor(port)), HttpFramingError);
    raw.shutdown();
  };

  SECTION("non-numeric Content-Length")
  {
    expectFramingThrow(19010, "HTTP/1.1 200 OK\r\nContent-Length: 12x\r\n\r\nXX");
  }
  SECTION("overflow chunk-size")
  {
    expectFramingThrow(19011, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                              "FFFFFFFFFFFFFFFF0\r\nx\r\n0\r\n\r\n");
  }
  SECTION("lone-LF chunk-size terminator")
  {
    expectFramingThrow(19012, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\nHELLO\r\n0\r\n\r\n");
  }
  SECTION("trailing space before CRLF with no chunk-ext")
  {
    expectFramingThrow(19013, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5 \r\nHELLO\r\n0\r\n\r\n");
  }
  SECTION("bare-CR in the chunk-size line is rejected (no lenient terminator)")
  {
    // "5\rHELLO..." — a bare CR after the size; the char after the hex run is not
    // ';'/CRLF, so it must be MALFORMED, never a silent truncated body.
    expectFramingThrow(19034, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\rHELLO\r\n0\r\n\r\n");
  }
}

// ── (i) both Content-Length and Transfer-Encoding -> reject ───────────────────
TEST_CASE("framing: Content-Length + Transfer-Encoding rejected", "[http_framing][smuggling]")
{
  const std::uint16_t port = 19014;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
                               "5\r\nHELLO\r\n0\r\n\r\n")));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  REQUIRE_THROWS_AS(client.get(urlFor(port)), HttpFramingError);
  raw.shutdown();
}

// ── (j) duplicate Content-Length: differ -> reject; identical list -> accept ──
TEST_CASE("framing: duplicate / list Content-Length handling", "[http_framing][contentlength]")
{
  SECTION("conflicting duplicate Content-Length is rejected")
  {
    const std::uint16_t port = 19015;
    RawServer raw;
    REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nHELLO")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE_THROWS_AS(client.get(urlFor(port)), HttpFramingError);
    raw.shutdown();
  }
  SECTION("identical comma-list Content-Length is accepted")
  {
    const std::uint16_t port = 19016;
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nHELLO")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body == "HELLO");
    raw.shutdown();
  }
}

// ── (k) obs-folded response header -> reject ──────────────────────────────────
TEST_CASE("framing: obs-fold header is rejected", "[http_framing][obsfold]")
{
  const std::uint16_t port = 19017;
  RawServer raw;
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nX-Test: a\r\n folded\r\nContent-Length: 0\r\n\r\n")));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  REQUIRE_THROWS_AS(client.get(urlFor(port)), HttpFramingError);
  raw.shutdown();
}

// ── (l)/(q)/(q+) Transfer-Encoding coding-list framing ────────────────────────
TEST_CASE("framing: Transfer-Encoding coding list (final-chunked vs not)", "[http_framing][te]")
{
  SECTION("chunked NOT final ('chunked, gzip') -> close-delimited (raw bytes)")
  {
    const std::uint16_t port = 19018;
    RawServer raw;
    REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nRAWBYTES")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body == "RAWBYTES"); // not chunk-framed on the wire -> read to close
    raw.shutdown();
  }
  SECTION("Transfer-Encoding: gzip (no chunked) -> close-delimited")
  {
    const std::uint16_t port = 19019;
    RawServer raw;
    REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nGZIPSTREAM")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "GZIPSTREAM");
    raw.shutdown();
  }
  SECTION("chunked final ('gzip, chunked', case-variant) -> de-chunk but NOT inflate")
  {
    const std::uint16_t port = 19020;
    // chunked is the final coding; the inner gzip octets are returned undecoded.
    // Use the gzip magic bytes + a NUL to prove binary-safe de-chunk-without-inflate.
    const std::string inner = std::string("\x1f\x8b\x08\x00", 4) + "GZ";
    const std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n6\r\n" +
                             inner + "\r\n0\r\n\r\n";
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive(resp)));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.body == inner); // de-chunked, still "gzip"-compressed octets (not inflated)
    REQUIRE(raw.acceptedCount() == 1);
    raw.shutdown();
  }
}

// ── (m) partial chunked body across many small reads -> NeedMore then Complete ─
TEST_CASE("framing: chunked body split across reads", "[http_framing][chunked][partial]")
{
  const std::uint16_t port = 19021;
  RawServer raw;
  REQUIRE(raw.start(port,
                    [](int cs)
                    {
                      readRequest(cs);
                      writeAll(cs, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
                      std::this_thread::sleep_for(std::chrono::milliseconds(30));
                      writeAll(cs, "5\r\nHE");
                      std::this_thread::sleep_for(std::chrono::milliseconds(30));
                      writeAll(cs, "LLO\r\n");
                      std::this_thread::sleep_for(std::chrono::milliseconds(30));
                      writeAll(cs, "0\r\n\r\n");
                    }));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  REQUIRE(client.get(urlFor(port)).body == "HELLO");
  raw.shutdown();
}

// ── (t) Content-Length body split across many small reads ─────────────────────
TEST_CASE("framing: content-length body split across reads", "[http_framing][contentlength][partial]")
{
  const std::uint16_t port = 19022;
  RawServer raw;
  REQUIRE(raw.start(port,
                    [](int cs)
                    {
                      readRequest(cs);
                      writeAll(cs, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n");
                      std::this_thread::sleep_for(std::chrono::milliseconds(30));
                      writeAll(cs, "ABCDE");
                      std::this_thread::sleep_for(std::chrono::milliseconds(30));
                      writeAll(cs, "FGHIJ");
                    }));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  REQUIRE(client.get(urlFor(port)).body == "ABCDEFGHIJ");
  raw.shutdown();
}

// ── (n) deterministic framing error is NOT retried ────────────────────────────
TEST_CASE("framing: deterministic framing error is not retried", "[http_framing][retry]")
{
  const std::uint16_t port = 19023;
  RawServer raw;
  // Both CL and TE -> framing error on every attempt.
  REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nX")));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  REQUIRE_THROWS_AS(client.get(urlFor(port), {}, /*retries=*/3), HttpFramingError);
  // Non-retryable: exactly one connection/attempt (a retry would reconnect -> >1).
  REQUIRE(raw.acceptedCount() == 1);
  raw.shutdown();
}

// ── (o)/(r) interim 1xx responses are skipped (single and multiple) ───────────
TEST_CASE("framing: interim 1xx responses are skipped", "[http_framing][interim]")
{
  SECTION("single 1xx then final")
  {
    const std::uint16_t port = 19024;
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 100 Continue\r\n\r\n"
                                      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body == "OK");
    raw.shutdown();
  }
  SECTION("multiple consecutive 1xx (103 then 100), some split across reads")
  {
    const std::uint16_t port = 19025;
    RawServer raw;
    REQUIRE(raw.start(port,
                      [](int cs)
                      {
                        readRequest(cs);
                        writeAll(cs, "HTTP/1.1 103 Early Hints\r\nLink: </s.css>"); // split mid-block
                        std::this_thread::sleep_for(std::chrono::milliseconds(30));
                        writeAll(cs, "\r\n\r\n");
                        std::this_thread::sleep_for(std::chrono::milliseconds(30));
                        writeAll(cs, "HTTP/1.1 100 Continue\r\n\r\n");
                        std::this_thread::sleep_for(std::chrono::milliseconds(30));
                        writeAll(cs, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nDONE");
                      }));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body == "DONE");
    raw.shutdown();
  }
}

// ── (s) zero-length bodies: close-delimited empty, and Content-Length: 0 reuse ─
TEST_CASE("framing: zero-length bodies", "[http_framing][empty]")
{
  SECTION("close-delimited zero-length body")
  {
    const std::uint16_t port = 19026;
    RawServer raw;
    REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\n\r\n")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.empty());
    raw.shutdown();
  }
  SECTION("Content-Length: 0 keeps the connection reusable")
  {
    const std::uint16_t port = 19027;
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body.empty());
    REQUIRE(client.get(urlFor(port)).body.empty());
    REQUIRE(raw.acceptedCount() == 1); // reused (not close-delimited)
    raw.shutdown();
  }
}

// ── eviction: surplus / server-close / close-delimited mark the connection
//    non-reusable, so the next same-host request opens a FRESH connection ──────
TEST_CASE("framing: connection is evicted (not reused) on surplus / close", "[http_framing][evict]")
{
  SECTION("surplus bytes after a Content-Length body -> body correct + evict")
  {
    const std::uint16_t port = 19030;
    RawServer raw;
    // 5-byte body "HELLO" plus 5 surplus bytes "EXTRA" on the wire.
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLOEXTRA")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(raw.acceptedCount() == 2); // surplus forced eviction -> reconnect
    raw.shutdown();
  }
  SECTION("server-sent Connection: close -> evict")
  {
    const std::uint16_t port = 19031;
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(raw.acceptedCount() == 2);
    raw.shutdown();
  }
  SECTION("surplus bytes after a chunked body -> body correct + evict")
  {
    const std::uint16_t port = 19032;
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                      "5\r\nHELLO\r\n0\r\n\r\nEXTRA")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(raw.acceptedCount() == 2);
    raw.shutdown();
  }
  SECTION("close-delimited response is never reused")
  {
    const std::uint16_t port = 19033;
    RawServer raw;
    // `once` closes after each response; the client must reconnect for request 2
    // (it must NOT attempt to reuse a connection it read to close).
    REQUIRE(raw.start(port, once("HTTP/1.1 200 OK\r\n\r\nCLOSEBODY")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "CLOSEBODY");
    REQUIRE(client.get(urlFor(port)).body == "CLOSEBODY");
    REQUIRE(raw.acceptedCount() == 2);
    raw.shutdown();
  }
}

// ── (p) regression: normal Content-Length and normal chunked, keep-alive reuse ─
TEST_CASE("framing: normal responses still parse and reuse", "[http_framing][regression]")
{
  SECTION("Content-Length keep-alive reuse")
  {
    const std::uint16_t port = 19028;
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(raw.acceptedCount() == 1);
    raw.shutdown();
  }
  SECTION("multi-chunk chunked body")
  {
    const std::uint16_t port = 19029;
    RawServer raw;
    REQUIRE(raw.start(port, keepAlive("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                      "5\r\nHELLO\r\n6\r\n WORLD\r\n0\r\n\r\n")));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO WORLD");
    REQUIRE(raw.acceptedCount() == 1);
    raw.shutdown();
  }
}
