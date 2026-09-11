// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// HttpClient::parseUrl hardening (tracker 2026-07-26-10 task-1.6 / defect_7 /
// defect_15, plus CLI-NEW1 / CLI-NEW2). parseUrl silently MIS-PARSED rather than
// rejecting: user:pass@host folded the credentials into the request-target,
// :65536 truncated to port 0, and a 20-digit port threw std::out_of_range into
// the retry path. The fix inspects the raw authority and REJECTS userinfo,
// parses the port strictly and validates 1..65535, and throws HttpInvalidUrlError
// — a std::invalid_argument (so the tmc_edge_proxy contract that a malformed URL
// surfaces as std::invalid_argument holds) that performRequest never retries.
// CLI-NEW1 makes the scheme case-insensitive (RFC 3986 §3.1) and CLI-NEW2 parses
// a bracketed IPv6 literal authority (RFC 3986 §3.2.2), re-bracketed onto the
// Host line by formatHostHeaderField. parseUrl is private, so URL faults are
// driven through the public API: they throw at the top of executeRequest BEFORE
// any connect, so a dead port cannot mask them. Catch2 macros run on the MAIN
// thread only. Run under ASan (handle_segv=0); ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include "network/http_client_test_server.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <type_traits>
#include <unistd.h>

using namespace iora::network;

namespace
{
using iora::test::httpsrv::makeListener;

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
      return;
    }
  }

  int _listenFd{-1};
  std::thread _thread;
  std::atomic<bool> _stop{false};
  mutable std::mutex _m;
  std::string _request;
};

HttpClient::Config cfg()
{
  HttpClient::Config c;
  c.requestTimeout = std::chrono::milliseconds(2000);
  c.connectTimeout = std::chrono::milliseconds(1000);
  c.reuseConnections = false;
  return c;
}

} // namespace

// HttpInvalidUrlError MUST remain a std::invalid_argument: tmc_edge_proxy's
// http_post primitive catches std::invalid_argument to convert a malformed URL
// into a fail action. It must NOT be an HttpFramingError / HttpRequestNotSentError
// (a std::runtime_error), or tmc's runtime_error catch ladder would swallow it.
TEST_CASE("HttpInvalidUrlError is a std::invalid_argument, not a runtime_error",
          "[http][parseurl][defect_7]")
{
  static_assert(std::is_base_of<std::invalid_argument,
                                iora::network::HttpInvalidUrlError>::value,
                "HttpInvalidUrlError must be a std::invalid_argument (tmc contract)");
  static_assert(!std::is_base_of<std::runtime_error,
                                 iora::network::HttpInvalidUrlError>::value,
                "HttpInvalidUrlError must NOT be a std::runtime_error");
  SUCCEED("HttpInvalidUrlError hierarchy verified at compile time");
}

// Userinfo is rejected — credentials must never reach the request-target. The
// throw precedes any connect, so a dead port cannot be the cause.
TEST_CASE("parseUrl rejects userinfo", "[http][parseurl][defect_7]")
{
  HttpClient client(cfg());
  for (const std::string url :
       {"http://user@127.0.0.1:1/rpc", "http://user:pass@127.0.0.1:1/rpc",
        "http://user:pass@127.0.0.1/rpc"})
  {
    CAPTURE(url);
    CHECK_THROWS_AS(client.get(url), iora::network::HttpInvalidUrlError);
    // And it IS-A std::invalid_argument (the cross-repo contract).
    CHECK_THROWS_AS(client.get(url), std::invalid_argument);
  }
}

// A WELL-FORMED bracketed IPv6 literal now PARSES (CLI-NEW2): parseUrl no longer
// rejects it as an invalid URL. Nothing is listening on [::1] here, so get()
// fails on the connect — but with a transport error, NOT HttpInvalidUrlError,
// which proves the URL parsed. A MALFORMED literal is still rejected.
TEST_CASE("parseUrl parses a bracketed IPv6 literal", "[http][parseurl][CLI-NEW2]")
{
  HttpClient client(cfg());
  for (const std::string url :
       {"http://[::1]:8080/rpc", "http://[2001:db8::1]/rpc", "http://[::1]/path",
        // Embedded-IPv4, full 8-group, and unspecified forms all parse.
        "http://[::ffff:192.0.2.1]/", "http://[2001:db8:0:0:0:0:0:1]/",
        "http://[::]/"})
  {
    CAPTURE(url);
    try
    {
      client.get(url);
    }
    catch (const iora::network::HttpInvalidUrlError &)
    {
      FAIL("a well-formed IPv6 literal must parse, not be rejected as an invalid URL");
    }
    catch (const std::exception &)
    {
      // A connect/transport failure is expected (no server) — the URL parsed.
    }
  }

  // The embedded-IPv4 literal re-brackets correctly onto the Host line.
  CHECK(formatHostHeaderField("::ffff:192.0.2.1", 80, false)
        == "Host: [::ffff:192.0.2.1]\r\n");

  // Malformed IPv6 literals (missing ']' / empty brackets) are still rejected.
  CHECK_THROWS_AS(client.get("http://[::1/rpc"), iora::network::HttpInvalidUrlError);
  CHECK_THROWS_AS(client.get("http://[]/rpc"), iora::network::HttpInvalidUrlError);
}

// H1: isIPAddress now uses inet_pton (not a loose IPv4 regex), so an out-of-range
// dotted quad is NOT an IP literal. Unbracketed, it is a reg-name host: parseUrl
// accepts it (no HttpInvalidUrlError) and it falls through to reg-name / DNS
// handling, failing later on connect/resolve rather than being rejected as a URL.
TEST_CASE("parseUrl treats an out-of-range dotted quad as a reg-name, not an IP literal",
          "[http][parseurl][H1]")
{
  HttpClient client(cfg());
  try
  {
    client.get("http://999.999.999.999/");
  }
  catch (const iora::network::HttpInvalidUrlError &)
  {
    FAIL("an out-of-range dotted quad is a reg-name host, not an invalid URL");
  }
  catch (const std::exception &)
  {
    // Connect/resolve failure expected (not a real host) — the URL parsed.
  }
}

// FIX-2: the bracket contents must be a REAL IPv6address (RFC 3986 §3.2.2), not
// merely non-empty bytes. Before the fix, `[garbage]` / `[]` / `[foo]` (colon-less)
// "parsed" — and a colon-less `[foo]` would then round-trip as a reg-name because
// formatHostHeaderField keys re-bracketing on ':'. All are now rejected, before any
// connect (so a dead port cannot be the cause). An RFC 6874 zone-id is REJECTED
// cleanly: inet_pton(AF_INET6) rejects the '%' it carries (we do not strip it).
TEST_CASE("parseUrl rejects non-IPv6 bracket contents", "[http][parseurl][CLI-NEW2]")
{
  HttpClient client(cfg());
  for (const std::string url :
       {"http://[garbage]/", "http://[]/", "http://[foo]/",
        // RFC 6874 zone-id (%25 == '%') — rejected, not stripped.
        "http://[fe80::1%25eth0]/rpc"})
  {
    CAPTURE(url);
    CHECK_THROWS_AS(client.get(url), iora::network::HttpInvalidUrlError);
    // And it IS-A std::invalid_argument (the cross-repo contract).
    CHECK_THROWS_AS(client.get(url), std::invalid_argument);
  }

  // A well-formed literal with an explicit port still parses (does not throw
  // HttpInvalidUrlError) and re-brackets onto the Host line: [::1]:8080. The Host
  // round-trip itself is proven by formatHostHeaderField below (no TLS server needed).
  try
  {
    client.get("http://[::1]:8080/path");
  }
  catch (const iora::network::HttpInvalidUrlError &)
  {
    FAIL("a well-formed IPv6 literal with a port must parse, not be rejected");
  }
  catch (const std::exception &)
  {
    // Connect/transport failure expected (no server) — the URL parsed.
  }
  CHECK(formatHostHeaderField("::1", 8080, false) == "Host: [::1]:8080\r\n");
}

// CLI-NEW2: the Host field MUST re-bracket an IPv6 literal (RFC 9112 §3.2 / RFC
// 7230). formatHostHeaderField is a pure free function, unit-testable without a
// socket. parseUrl stores the literal WITHOUT brackets, so this is the wire
// round-trip check. IPv4 / reg-name hosts stay unbracketed.
TEST_CASE("formatHostHeaderField brackets an IPv6 literal", "[http][parseurl][CLI-NEW2]")
{
  CHECK(formatHostHeaderField("::1", 8080, false) == "Host: [::1]:8080\r\n");
  CHECK(formatHostHeaderField("2001:db8::1", 443, true) == "Host: [2001:db8::1]\r\n");
  // Default port omitted, brackets retained.
  CHECK(formatHostHeaderField("::1", 80, false) == "Host: [::1]\r\n");
  CHECK(formatHostHeaderField("127.0.0.1", 8080, false) == "Host: 127.0.0.1:8080\r\n");
  CHECK(formatHostHeaderField("example.com", 80, false) == "Host: example.com\r\n");
}

// Port must be 1..65535: :0, :65536 (formerly truncated to port 0), and an
// overflowing digit run (formerly std::out_of_range into the retry path) all
// throw HttpInvalidUrlError.
TEST_CASE("parseUrl validates the port range", "[http][parseurl][defect_15]")
{
  HttpClient client(cfg());
  for (const std::string url :
       {"http://127.0.0.1:0/rpc", "http://127.0.0.1:65536/rpc",
        "http://127.0.0.1:99999/rpc",
        "http://127.0.0.1:12345678901234567890/rpc"})
  {
    CAPTURE(url);
    CHECK_THROWS_AS(client.get(url), iora::network::HttpInvalidUrlError);
  }
}

// A malformed URL still throws with the byte-identical legacy message (the tmc
// contract keys nothing on the message, but preserving it is cheap and safe).
// An uppercase scheme now PARSES (CLI-NEW1, RFC 3986 §3.1 case-insensitive):
// drive it against a live server to prove parse + connect + a well-formed
// request, not merely "did not throw".
TEST_CASE("parseUrl rejects malformed URLs but accepts an uppercase scheme",
          "[http][parseurl][CLI-NEW1]")
{
  HttpClient client(cfg());
  try
  {
    client.get("not-a-url");
    FAIL("expected a throw");
  }
  catch (const iora::network::HttpInvalidUrlError &e)
  {
    CHECK(std::string(e.what()).rfind("Invalid URL format: ", 0) == 0);
  }

  const std::uint16_t port = 65534;
  CapturingServer server;
  REQUIRE(server.start(port));

  const std::string url = "HTTP://127.0.0.1:" + std::to_string(port) + "/rpc";
  auto resp = client.get(url);
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  // The canonicalized (lowercase) scheme still emits a correct Host line.
  CHECK(req.find("Host: 127.0.0.1:65534\r\n") != std::string::npos);
}

// A valid explicit port parses and the client connects to it — the fix does not
// false-positive on a well-formed authority. 65535 is the boundary value.
TEST_CASE("parseUrl accepts a valid high port and connects", "[http][parseurl]")
{
  const std::uint16_t port = 65535;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/rpc";
  auto resp = client.get(url);
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  // The non-default port is carried on the Host line (task-1.7(a) already).
  CHECK(req.find("Host: 127.0.0.1:65535\r\n") != std::string::npos);
  // No credential ever appears in the request-target.
  CHECK(req.find("@") == std::string::npos);
}
