// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// RFC 9110 §5.5 / §5.6.2 caller header-name and -value validation in HttpClient
// (tracker 2026-07-26-10 task-1.2 / defect_1 / defect_3). executeRequest wrote
// every caller header straight to the wire, so a CR/LF in a value injected
// header lines or an entire smuggled request. The fix validates the caller
// `headers` map at the top of executeRequest (before any connect) and throws
// HttpInvalidHeaderError — a non-retryable HttpFramingError subclass. The pure
// validators (isValidHttpFieldName / isValidHttpFieldValue) are unit-tested
// without a socket; a mock server confirms a valid header still flows and the
// injecting call throws BEFORE any connect. Catch2 macros run on the MAIN
// thread only; the server records under a mutex. Run under ASan (handle_segv=0);
// ctest -j1.

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
#include <type_traits>
#include <unistd.h>

using namespace iora::network;

namespace
{
using iora::test::httpsrv::makeListener;

/// \brief One-shot raw server: captures the first request's header block and
/// replies 200 OK, so a test can assert what actually reached the wire.
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
      return; // one-shot
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

// ---------------------------------------------------------------------------
// Socket-free unit tests of the pure validators (task-1.2 / defect_1/defect_3).
// ---------------------------------------------------------------------------

TEST_CASE("isValidHttpFieldName accepts RFC 9110 tokens, rejects non-tchar",
          "[http][validation][defect_3]")
{
  using iora::network::isValidHttpFieldName;
  // Valid tokens: ALPHA / DIGIT / the tchar specials.
  CHECK(isValidHttpFieldName("Content-Type"));
  CHECK(isValidHttpFieldName("X-Custom-Header"));
  CHECK(isValidHttpFieldName("X_Foo.9"));
  CHECK(isValidHttpFieldName("!#$%&'*+-.^_`|~"));
  // Empty name is not a token.
  CHECK_FALSE(isValidHttpFieldName(""));
  // Whitespace anywhere (incl. a trailing space before the colon, RFC 9112 §5.1).
  CHECK_FALSE(isValidHttpFieldName("X-Foo "));
  CHECK_FALSE(isValidHttpFieldName(" X-Foo"));
  CHECK_FALSE(isValidHttpFieldName("X Foo"));
  // Separators are NOT tchar — including '<' and '>' that a hand-written
  // deny-list commonly forgets (web L2).
  for (const std::string bad :
       {"X-Foo(", "X-Foo)", "X@Foo", "X,Foo", "X;Foo", "X:Foo", "X\\Foo",
        "X\"Foo", "X/Foo", "X[Foo", "X]Foo", "X?Foo", "X=Foo", "X{Foo",
        "X}Foo", "X<Foo", "X>Foo"})
  {
    CHECK_FALSE(isValidHttpFieldName(bad));
  }
  // Control octets and DEL in a name are rejected.
  CHECK_FALSE(isValidHttpFieldName(std::string("X\x7F""Foo")));
  CHECK_FALSE(isValidHttpFieldName(std::string("X\x01""Foo")));
}

TEST_CASE("isValidHttpFieldValue enforces the RFC 9110 §5.5 field-value grammar",
          "[http][validation][defect_1]")
{
  using iora::network::isValidHttpFieldValue;
  // Ordinary values, empty value, HTAB, and obs-text (0x80-0xFF) are permitted.
  CHECK(isValidHttpFieldValue("application/json"));
  CHECK(isValidHttpFieldValue(""));
  CHECK(isValidHttpFieldValue("a\tb"));           // HTAB allowed
  CHECK(isValidHttpFieldValue(std::string("caf\xC3\xA9"))); // obs-text (UTF-8)
  CHECK(isValidHttpFieldValue(std::string("\x80\xFF")));    // obs-text bytes
  // CR, LF, NUL — the header/request-line injection vectors.
  CHECK_FALSE(isValidHttpFieldValue("bar\r\nX-Injected: 1"));
  CHECK_FALSE(isValidHttpFieldValue("bar\roops"));
  CHECK_FALSE(isValidHttpFieldValue("bar\noops"));
  CHECK_FALSE(isValidHttpFieldValue(std::string("bar\x00oops", 8)));
  // VT (0x0B) and FF (0x0C) that a naive CR/LF/NUL filter passes.
  CHECK_FALSE(isValidHttpFieldValue(std::string("bar\x0Boops")));
  CHECK_FALSE(isValidHttpFieldValue(std::string("bar\x0Coops")));
  // DEL (0x7F) is rejected; other controls too.
  CHECK_FALSE(isValidHttpFieldValue(std::string("bar\x7Foops")));
  CHECK_FALSE(isValidHttpFieldValue(std::string("bar\x1Foops")));
}

// ---------------------------------------------------------------------------
// Wire behavior: the guard fires BEFORE any connect, and a valid header flows.
// ---------------------------------------------------------------------------

// An injecting value throws HttpInvalidHeaderError. The URL points at a port
// with NO listener: if the guard were removed, executeRequest would proceed to
// connect and surface a connect/not-sent error instead — so getting
// HttpInvalidHeaderError proves the throw precedes any connect (nothing reaches
// the socket). Mutation-test: deleting the guard changes the thrown type.
TEST_CASE("executeRequest throws before connect on a CRLF-injection value",
          "[http][validation][defect_1]")
{
  HttpClient client(cfg());
  const std::string deadUrl = "http://127.0.0.1:1/rpc"; // port 1: no listener
  CHECK_THROWS_AS(client.get(deadUrl, {{"X-Foo", "bar\r\nX-Injected: 1"}}),
                  iora::network::HttpInvalidHeaderError);
  // A non-token name likewise throws before connect.
  CHECK_THROWS_AS(client.get(deadUrl, {{"X Bad Name", "ok"}}),
                  iora::network::HttpInvalidHeaderError);
}

// A well-formed caller header reaches the wire unchanged (the guard does not
// false-positive), and no spurious "X-Injected" line appears.
TEST_CASE("A valid caller header flows to the wire", "[http][validation][defect_1]")
{
  const std::uint16_t port = 18194;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/rpc";
  auto resp = client.get(url, {{"X-Foo", "bar"}});
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  CHECK(req.find("X-Foo: bar\r\n") != std::string::npos);
  CHECK(req.find("X-Injected") == std::string::npos);
}

// The validation exception is a non-retryable HttpFramingError, NOT an
// HttpRequestNotSentError (which would misapply "not sent => retry any method").
// Verified at COMPILE TIME: the derivation from HttpFramingError and the absence
// of any HttpRequestNotSentError base are static facts (a runtime dynamic_cast
// to an unrelated type is a -Werror "can never succeed").
TEST_CASE("HttpInvalidHeaderError is a non-retryable HttpFramingError",
          "[http][validation][defect_1]")
{
  static_assert(std::is_base_of<iora::network::HttpFramingError,
                                iora::network::HttpInvalidHeaderError>::value,
                "validation error must be a non-retryable HttpFramingError");
  static_assert(!std::is_base_of<iora::network::HttpRequestNotSentError,
                                 iora::network::HttpInvalidHeaderError>::value,
                "validation error must NOT be an HttpRequestNotSentError");
  SUCCEED("HttpInvalidHeaderError hierarchy verified at compile time");
}
