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

#include "network/http_client_test_server.hpp"
#include <iora/network/http_client.hpp>

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

using iora::test::httpsrv::writeAll;

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
  bool start(RawHandler handler)
  {
    _listenFd = iora::test::httpsrv::makeListener();
    if (_listenFd < 0)
    {
      return false;
    }
    _handler = std::move(handler);
    _thread = std::thread([this] { run(); });
    return true;
  }

  std::uint16_t port() const { return iora::test::httpsrv::listenerPort(_listenFd); }

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
  RawServer raw;
  REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\n\r\nHELLO-CLOSE-DELIMITED-BODY")));
  const std::uint16_t port = raw.port();
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
  // body "abc0\r\n\r\ndef" is 11 octets (0x0b); the bytes "0\r\n\r\n" appear INSIDE it.
  const std::string resp =
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\nabc0\r\n\r\ndef\r\n0\r\n\r\n";
  RawServer raw;
  REQUIRE(raw.start(keepAlive(resp)));
  const std::uint16_t port = raw.port();
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
  // "05" leading zero; chunk-ext "; name = \"v;al\"" with BWS around ';' and '='.
  const std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                           "05 ; name = \"v;al\"\r\nHELLO\r\n0\r\n\r\n";
  RawServer raw;
  REQUIRE(raw.start(once(resp)));
  const std::uint16_t port = raw.port();
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
  const std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                           "5\r\nHELLO\r\n0\r\nX-Trace: abc\r\nX-More: 1\r\n\r\n";
  RawServer raw;
  REQUIRE(raw.start(keepAlive(resp)));
  const std::uint16_t port = raw.port();
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
  RawServer raw;
  REQUIRE(raw.start(keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")));
  const std::uint16_t port = raw.port();
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
    RawServer raw;
    REQUIRE(raw.start(keepAlive("HTTP/1.1 204 No Content\r\n\r\n")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 204);
    REQUIRE(r.body.empty());
    raw.shutdown();
  }
  SECTION("304 Not Modified with a phantom Content-Length")
  {
    RawServer raw;
    REQUIRE(raw.start(keepAlive("HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\n\r\n")));
    const std::uint16_t port = raw.port();
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
    RawServer raw;
    REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\n\r\n" + std::string(20000, 'X'))));
    const std::uint16_t port = raw.port();
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
    RawServer raw;
    REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")));
    const std::uint16_t port = raw.port();
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
    RawServer raw;
    REQUIRE(raw.start(once(std::string(20000, 'X')))); // never a \r\n\r\n
    const std::uint16_t port = raw.port();
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
  auto expectFramingThrow = [](const std::string &resp)
  {
    RawServer raw;
    REQUIRE(raw.start(once(resp)));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE_THROWS_AS(client.get(urlFor(port)), HttpFramingError);
    raw.shutdown();
  };

  SECTION("non-numeric Content-Length")
  {
    expectFramingThrow("HTTP/1.1 200 OK\r\nContent-Length: 12x\r\n\r\nXX");
  }
  SECTION("overflow chunk-size")
  {
    expectFramingThrow("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                       "FFFFFFFFFFFFFFFF0\r\nx\r\n0\r\n\r\n");
  }
  SECTION("lone-LF chunk-size terminator")
  {
    expectFramingThrow("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\nHELLO\r\n0\r\n\r\n");
  }
  SECTION("trailing space before CRLF with no chunk-ext")
  {
    expectFramingThrow("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5 \r\nHELLO\r\n0\r\n\r\n");
  }
  SECTION("bare-CR in the chunk-size line is rejected (no lenient terminator)")
  {
    // "5\rHELLO..." — a bare CR after the size; the char after the hex run is not
    // ';'/CRLF, so it must be MALFORMED, never a silent truncated body.
    expectFramingThrow("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\rHELLO\r\n0\r\n\r\n");
  }
}

// ── (i) both Content-Length and Transfer-Encoding -> reject ───────────────────
TEST_CASE("framing: Content-Length + Transfer-Encoding rejected", "[http_framing][smuggling]")
{
  RawServer raw;
  REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
                               "5\r\nHELLO\r\n0\r\n\r\n")));
  const std::uint16_t port = raw.port();
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
    RawServer raw;
    REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nHELLO")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE_THROWS_AS(client.get(urlFor(port)), HttpFramingError);
    raw.shutdown();
  }
  SECTION("identical comma-list Content-Length is accepted")
  {
    RawServer raw;
    REQUIRE(raw.start(keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nHELLO")));
    const std::uint16_t port = raw.port();
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
  RawServer raw;
  REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\nX-Test: a\r\n folded\r\nContent-Length: 0\r\n\r\n")));
  const std::uint16_t port = raw.port();
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
    RawServer raw;
    REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nRAWBYTES")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body == "RAWBYTES"); // not chunk-framed on the wire -> read to close
    raw.shutdown();
  }
  SECTION("Transfer-Encoding: gzip (no chunked) -> close-delimited")
  {
    RawServer raw;
    REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nGZIPSTREAM")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "GZIPSTREAM");
    raw.shutdown();
  }
  SECTION("chunked final ('gzip, chunked', case-variant) -> de-chunk but NOT inflate")
  {
    // chunked is the final coding; the inner gzip octets are returned undecoded.
    // Use the gzip magic bytes + a NUL to prove binary-safe de-chunk-without-inflate.
    const std::string inner = std::string("\x1f\x8b\x08\x00", 4) + "GZ";
    const std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n6\r\n" +
                             inner + "\r\n0\r\n\r\n";
    RawServer raw;
    REQUIRE(raw.start(keepAlive(resp)));
    const std::uint16_t port = raw.port();
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
  RawServer raw;
  REQUIRE(raw.start([](int cs)
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
  const std::uint16_t port = raw.port();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  REQUIRE(client.get(urlFor(port)).body == "HELLO");
  raw.shutdown();
}

// ── (t) Content-Length body split across many small reads ─────────────────────
TEST_CASE("framing: content-length body split across reads", "[http_framing][contentlength][partial]")
{
  RawServer raw;
  REQUIRE(raw.start([](int cs)
                    {
                      readRequest(cs);
                      writeAll(cs, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n");
                      std::this_thread::sleep_for(std::chrono::milliseconds(30));
                      writeAll(cs, "ABCDE");
                      std::this_thread::sleep_for(std::chrono::milliseconds(30));
                      writeAll(cs, "FGHIJ");
                    }));
  const std::uint16_t port = raw.port();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  REQUIRE(client.get(urlFor(port)).body == "ABCDEFGHIJ");
  raw.shutdown();
}

// ── (n) deterministic framing error is NOT retried ────────────────────────────
TEST_CASE("framing: deterministic framing error is not retried", "[http_framing][retry]")
{
  RawServer raw;
  // Both CL and TE -> framing error on every attempt.
  REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nX")));
  const std::uint16_t port = raw.port();
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
    RawServer raw;
    REQUIRE(raw.start(keepAlive("HTTP/1.1 100 Continue\r\n\r\n"
                                      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body == "OK");
    raw.shutdown();
  }
  SECTION("multiple consecutive 1xx (103 then 100), some split across reads")
  {
    RawServer raw;
    REQUIRE(raw.start([](int cs)
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
    const std::uint16_t port = raw.port();
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
    RawServer raw;
    REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\n\r\n")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    auto r = client.get(urlFor(port));
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.empty());
    raw.shutdown();
  }
  SECTION("Content-Length: 0 keeps the connection reusable")
  {
    RawServer raw;
    REQUIRE(raw.start(keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")));
    const std::uint16_t port = raw.port();
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
    RawServer raw;
    // 5-byte body "HELLO" plus 5 surplus bytes "EXTRA" on the wire.
    REQUIRE(raw.start(keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLOEXTRA")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(raw.acceptedCount() == 2); // surplus forced eviction -> reconnect
    raw.shutdown();
  }
  SECTION("server-sent Connection: close -> evict")
  {
    RawServer raw;
    REQUIRE(raw.start(keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(raw.acceptedCount() == 2);
    raw.shutdown();
  }
  SECTION("surplus bytes after a chunked body -> body correct + evict")
  {
    RawServer raw;
    REQUIRE(raw.start(keepAlive("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                      "5\r\nHELLO\r\n0\r\n\r\nEXTRA")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(raw.acceptedCount() == 2);
    raw.shutdown();
  }
  SECTION("close-delimited response is never reused")
  {
    RawServer raw;
    // `once` closes after each response; the client must reconnect for request 2
    // (it must NOT attempt to reuse a connection it read to close).
    REQUIRE(raw.start(once("HTTP/1.1 200 OK\r\n\r\nCLOSEBODY")));
    const std::uint16_t port = raw.port();
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
    RawServer raw;
    REQUIRE(raw.start(keepAlive("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(client.get(urlFor(port)).body == "HELLO");
    REQUIRE(raw.acceptedCount() == 1);
    raw.shutdown();
  }
  SECTION("multi-chunk chunked body")
  {
    RawServer raw;
    REQUIRE(raw.start(keepAlive("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                      "5\r\nHELLO\r\n6\r\n WORLD\r\n0\r\n\r\n")));
    const std::uint16_t port = raw.port();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    HttpClient client(cfg());
    REQUIRE(client.get(urlFor(port)).body == "HELLO WORLD");
    REQUIRE(raw.acceptedCount() == 1);
    raw.shutdown();
  }
}

// ── (i) split-segment / surplus-octet eviction scoping (tracker 2026-07-26-4
// task-5.1) ───────────────────────────────────────────────────────────────────
TEST_CASE("framing: a bodyless 204 carrying surplus body octets EVICTS the connection",
          "[http_framing][nobody][evict]")
{
  // A non-conformant 204 that declares Content-Length: 9 and puts 9 body octets on
  // the wire (RFC 9112 §6.3 rule 1 forbids a body). The client must frame it as
  // bodyless AND evict the connection rather than pool it dirty — otherwise a
  // subsequent keep-alive request would parse "Not Found" as the next status line.
  RawServer raw;
  REQUIRE(raw.start(keepAlive("HTTP/1.1 204 No Content\r\nContent-Length: 9\r\n\r\nNot Found")));
  const std::uint16_t port = raw.port();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  auto r1 = client.get(urlFor(port));
  REQUIRE(r1.statusCode == 204);
  REQUIRE(r1.body.empty());
  auto r2 = client.get(urlFor(port));
  REQUIRE(r2.statusCode == 204);
  // Eviction: the second request opened a NEW connection (the dirty one was not
  // reused). Pre-fix (unconditional-reuse) this would be 1.
  REQUIRE(raw.acceptedCount() == 2);
  raw.shutdown();
}

TEST_CASE("framing: a conformant keep-alive 304 with Content-Length is REUSED, not evicted",
          "[http_framing][nobody][evict]")
{
  // A conformant 304 MAY carry Content-Length equal to the 200-response octet count
  // while putting ZERO body octets on the wire (RFC 9110 §8.6 / RFC 9112 §6.3 rule
  // 1). Evicting it would defeat the cache-validation keep-alive reuse a 304 exists
  // for, so the client must NOT evict on a declared length alone — only on ARRIVED
  // surplus. Two requests must share ONE connection.
  RawServer raw;
  REQUIRE(raw.start(keepAlive("HTTP/1.1 304 Not Modified\r\nContent-Length: 50\r\n\r\n")));
  const std::uint16_t port = raw.port();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  auto r1 = client.get(urlFor(port));
  REQUIRE(r1.statusCode == 304);
  REQUIRE(r1.body.empty());
  auto r2 = client.get(urlFor(port));
  REQUIRE(r2.statusCode == 304);
  REQUIRE(r2.body.empty());
  REQUIRE(raw.acceptedCount() == 1); // reused, not evicted
  raw.shutdown();
}

TEST_CASE("framing: a bodyless 204 declaring Transfer-Encoding (no CL) EVICTS the connection",
          "[http_framing][nobody][evict]")
{
  // Symmetric to the Content-Length case: a 204 that declares Transfer-Encoding
  // with no body octets in this segment is non-conformant (RFC 9112 §6.1) and its
  // phantom chunk data may arrive later; the client must evict, not pool dirty.
  RawServer raw;
  REQUIRE(raw.start(keepAlive("HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n")));
  const std::uint16_t port = raw.port();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  auto r1 = client.get(urlFor(port));
  REQUIRE(r1.statusCode == 204);
  REQUIRE(r1.body.empty());
  auto r2 = client.get(urlFor(port));
  REQUIRE(r2.statusCode == 204);
  REQUIRE(raw.acceptedCount() == 2); // evicted -> second request opened a new connection
  raw.shutdown();
}

TEST_CASE("framing: a bodyless 204 with a MALFORMED Content-Length EVICTS the connection",
          "[http_framing][nobody][evict]")
{
  // A 204 declaring a non-numeric Content-Length is non-conformant; the eviction
  // guard's parseContentLength throws and the fail-safe default (evict) applies, so
  // the connection is not pooled dirty.
  RawServer raw;
  REQUIRE(raw.start(keepAlive("HTTP/1.1 204 No Content\r\nContent-Length: notanumber\r\n\r\n")));
  const std::uint16_t port = raw.port();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  HttpClient client(cfg());
  auto r1 = client.get(urlFor(port));
  REQUIRE(r1.statusCode == 204);
  REQUIRE(r1.body.empty());
  auto r2 = client.get(urlFor(port));
  REQUIRE(r2.statusCode == 204);
  REQUIRE(raw.acceptedCount() == 2); // evicted (fail-safe on malformed CL)
  raw.shutdown();
}
