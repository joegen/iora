// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for HttpClient automatic-retry idempotency safety (tracker 2026-06-14-7).
// A non-idempotent method (POST/PATCH/...) must NOT be auto-retried once the
// request may have reached the wire (RFC 9110 §9.2.2 — no double-submit), while
// idempotent methods (GET/HEAD/PUT/DELETE/OPTIONS/TRACE) retry as before, and a
// request that provably never reached the wire (connect/sync-setup failure)
// retries regardless of method.
//
// Catch2 assertion macros are invoked ONLY on the main thread; the mock server
// runs on its own std::thread and records counts into atomics that the main
// thread asserts. Run under TSan (setarch -R) and ASan (handle_segv=0).

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include <arpa/inet.h>
#include <atomic>
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

// ── Raw mock HTTP server ────────────────────────────────────────────────────
// A minimal listener that lets a test control the EXACT failure mode (close
// after reading the request, write a partial response then close, never
// respond) and COUNT how many requests reached the wire — the core mechanism
// for proving a request was or was not retried.

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

// Read one request's header block (clientSock has a recv timeout). Returns true
// if a full "\r\n\r\n"-terminated request header block arrived.
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
      return false; // closed or timeout
    }
  }
  return false;
}

/// \brief Per-connection handler: (clientSock, connectionIndex) -> reply/close.
using RawHandler = std::function<void(int, int)>;

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

  // Number of connections accepted (== connect attempts that succeeded).
  int acceptedCount() const { return _accepted.load(); }
  // Number of full request header blocks received (== requests reaching the
  // wire). This is the no-double-submit assertion target.
  int requestsReceived() const { return _requests.load(); }

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
        int idx = _accepted.fetch_add(1);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 300 * 1000;
        ::setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (readRequest(cs))
        {
          _requests.fetch_add(1);
        }
        _handler(cs, idx);
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
  std::atomic<int> _requests{0};
  RawHandler _handler;
};

// Handler: request already read by run(); close immediately without responding.
RawHandler closeAfterReadHandler()
{
  return [](int /*clientSock*/, int /*idx*/) {};
}

// Handler: write a partial status line then close (server clearly began
// processing — possibly-processed).
RawHandler partialResponseHandler()
{
  return [](int clientSock, int /*idx*/) { writeAll(clientSock, "HTTP/1.1 2"); };
}

// Handler: never respond; hold the socket briefly so the client request times
// out (request fully delivered -> possibly-processed).
RawHandler timeoutHandler()
{
  return [](int /*clientSock*/, int /*idx*/)
  { std::this_thread::sleep_for(std::chrono::milliseconds(400)); };
}

// Handler: reply with a complete, valid 200 response then close.
RawHandler okHandler()
{
  return [](int clientSock, int /*idx*/)
  {
    const std::string body = "ok";
    std::string r = "HTTP/1.1 200 OK\r\n";
    r += "Content-Type: text/plain\r\n";
    r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    r += "Connection: close\r\n\r\n";
    r += body;
    writeAll(clientSock, r);
  };
}

std::string url(std::uint16_t port, const std::string &path)
{
  return "http://127.0.0.1:" + std::to_string(port) + path;
}

// A client with short localhost timeouts so the timeout/connect-fail tests run
// fast and deterministically.
HttpClient makeClient()
{
  return HttpClient(HttpClient::Config::forLocalhost());
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════
// T10: isIdempotentMethod classification (the pure RFC 9110 §9.2.2 classifier).
//      Exact, case-sensitive; everything else (incl. wrong-case / whitespace /
//      extension / CONNECT) is non-idempotent. CONNECT is covered here ONLY —
//      the client cannot form a valid CONNECT request.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("isIdempotentMethod: exact-case idempotent set", "[http_client_retry][classify]")
{
  CHECK(HttpClient::isIdempotentMethod("GET"));
  CHECK(HttpClient::isIdempotentMethod("HEAD"));
  CHECK(HttpClient::isIdempotentMethod("PUT"));
  CHECK(HttpClient::isIdempotentMethod("DELETE"));
  CHECK(HttpClient::isIdempotentMethod("OPTIONS"));
  CHECK(HttpClient::isIdempotentMethod("TRACE"));
}

TEST_CASE("isIdempotentMethod: non-idempotent and malformed tokens", "[http_client_retry][classify]")
{
  // Non-idempotent registered methods.
  CHECK_FALSE(HttpClient::isIdempotentMethod("POST"));
  CHECK_FALSE(HttpClient::isIdempotentMethod("PATCH"));
  CHECK_FALSE(HttpClient::isIdempotentMethod("CONNECT"));
  // Extension / empty.
  CHECK_FALSE(HttpClient::isIdempotentMethod("FOO"));
  CHECK_FALSE(HttpClient::isIdempotentMethod(""));
  // Wrong case — RFC 9110 §9.1: method tokens are case-sensitive.
  CHECK_FALSE(HttpClient::isIdempotentMethod("get"));
  CHECK_FALSE(HttpClient::isIdempotentMethod("Post"));
  // Whitespace padding must NOT be trimmed/accepted.
  CHECK_FALSE(HttpClient::isIdempotentMethod(" GET"));
  CHECK_FALSE(HttpClient::isIdempotentMethod("GET "));
  CHECK_FALSE(HttpClient::isIdempotentMethod("get "));
}

// ══════════════════════════════════════════════════════════════════════════
// T1: POST that fails AFTER the request reached the wire is NOT retried.
//     (server reads the full request, then closes without responding)
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("POST not retried after request sent (no double-submit)", "[http_client_retry][post]")
{
  const std::uint16_t port = 18801;
  RawServer server;
  REQUIRE(server.start(port, closeAfterReadHandler()));

  HttpClient client = makeClient();

  bool threw = false;
  bool wasNotSentType = false;
  try
  {
    client.post(url(port, "/x"), "payload", {}, /*retries=*/2);
  }
  catch (const HttpRequestNotSentError &)
  {
    threw = true;
    wasNotSentType = true; // would be WRONG for a post-send failure
  }
  catch (const std::exception &)
  {
    threw = true;
  }

  CHECK(threw);
  // Classification boundary: a post-send failure must NOT surface as not-sent.
  CHECK_FALSE(wasNotSentType);
  // The core guarantee: the server saw the request exactly once.
  CHECK(server.requestsReceived() == 1);
}

// ══════════════════════════════════════════════════════════════════════════
// T2: GET that fails after send IS retried (idempotent) — retries+1 attempts.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("GET retried after request sent (idempotent)", "[http_client_retry][get]")
{
  const std::uint16_t port = 18802;
  RawServer server;
  REQUIRE(server.start(port, closeAfterReadHandler()));

  HttpClient client = makeClient();

  CHECK_THROWS(client.get(url(port, "/x"), {}, /*retries=*/2));
  CHECK(server.requestsReceived() == 3); // initial + 2 retries
}

// ══════════════════════════════════════════════════════════════════════════
// T3: DELETE (idempotent, publicly reachable) is retried after send. Proves the
//     idempotent retry path for a non-GET method. (PUT/PATCH end-to-end is not
//     issuable via the public API; their behavior follows by composition of the
//     classifier (above) and the gate proven by T1/T2/T3 — see DEC-4.)
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("DELETE retried after request sent (idempotent, non-GET)", "[http_client_retry][delete]")
{
  const std::uint16_t port = 18803;
  RawServer server;
  REQUIRE(server.start(port, closeAfterReadHandler()));

  HttpClient client = makeClient();

  CHECK_THROWS(client.deleteRequest(url(port, "/x"), {}, /*retries=*/1));
  CHECK(server.requestsReceived() == 2); // initial + 1 retry
}

// ══════════════════════════════════════════════════════════════════════════
// T5: Partial-response-then-reset (server clearly began processing). POST must
//     not retry; GET mirror retries.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("POST not retried when server sends a partial response then closes",
          "[http_client_retry][post][partial]")
{
  const std::uint16_t port = 18805;
  RawServer server;
  REQUIRE(server.start(port, partialResponseHandler()));

  HttpClient client = makeClient();

  CHECK_THROWS(client.post(url(port, "/x"), "payload", {}, /*retries=*/2));
  CHECK(server.requestsReceived() == 1);
}

TEST_CASE("GET retried when server sends a partial response then closes",
          "[http_client_retry][get][partial]")
{
  const std::uint16_t port = 18806;
  RawServer server;
  REQUIRE(server.start(port, partialResponseHandler()));

  HttpClient client = makeClient();

  CHECK_THROWS(client.get(url(port, "/x"), {}, /*retries=*/2));
  CHECK(server.requestsReceived() == 3);
}

// ══════════════════════════════════════════════════════════════════════════
// T6: Timeout-stage POST (request fully delivered, server never responds) is
//     not retried.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("POST not retried on response timeout", "[http_client_retry][post][timeout]")
{
  const std::uint16_t port = 18807;
  RawServer server;
  REQUIRE(server.start(port, timeoutHandler()));

  HttpClient client = makeClient();

  CHECK_THROWS(client.post(url(port, "/x"), "payload", {}, /*retries=*/2));
  CHECK(server.requestsReceived() == 1);
}

// ══════════════════════════════════════════════════════════════════════════
// T7/T8: Connect failure (no listener) = provably-unsent -> retried for ANY
//        method, including POST. A server-side connect-attempt count is
//        impossible (nothing accepts a refused connection), so per tracker T7
//        we prove the retry by TIMING. To stay robust under sanitizers (which
//        inflate the absolute connect cost — an absolute upper bound on the
//        no-retry path is fragile), we measure the DELTA between retries=1 and
//        retries=0: the retry path performs exactly one extra backoff sleep
//        ((1<<0)*100 + jitter = 100-199 ms) that the no-retry path does not.
//        That deterministic wall-clock sleep does NOT scale with sanitizer
//        overhead, so the delta isolates the retry signal from connect cost.
//        The retries=1 case is measured FIRST so any cold-start connect cost is
//        absorbed into the larger value, keeping the delta a clean lower bound.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("connect-fail POST is retried; the retry adds one backoff (provably unsent)",
          "[http_client_retry][post][connect]")
{
  HttpClient client = makeClient();

  auto measure = [&](int retries, std::uint16_t deadPort)
  {
    bool threw = false;
    auto t0 = std::chrono::steady_clock::now();
    try
    {
      client.post(url(deadPort, "/x"), "payload", {}, retries);
    }
    catch (const std::exception &)
    {
      threw = true;
    }
    CHECK(threw);
    return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0)
      .count();
  };

  // Measure the retried case first (absorbs cold-start connect cost), then the
  // single-attempt case. Both ports have no listener -> connect refused ->
  // HttpRequestNotSentError -> retried even for POST.
  auto withRetry = measure(/*retries=*/1, 19111);
  auto noRetry = measure(/*retries=*/0, 19112);

  // A retry definitely slept one backoff window.
  CHECK(withRetry >= 90);
  // The retry added exactly one backoff sleep the no-retry path lacks; the delta
  // isolates that sleep from the (sanitizer-inflated) connect cost.
  CHECK(withRetry - noRetry >= 80);
}

// ══════════════════════════════════════════════════════════════════════════
// T9: Default retries=0 -> exactly one attempt for POST and GET (no behavior
//     change for the default path).
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("default retries=0 makes a single attempt for POST and GET",
          "[http_client_retry][default]")
{
  {
    const std::uint16_t port = 18809;
    RawServer server;
    REQUIRE(server.start(port, closeAfterReadHandler()));
    HttpClient client = makeClient();
    CHECK_THROWS(client.post(url(port, "/x"), "payload", {}, /*retries=*/0));
    CHECK(server.requestsReceived() == 1);
  }
  {
    const std::uint16_t port = 18810;
    RawServer server;
    REQUIRE(server.start(port, closeAfterReadHandler()));
    HttpClient client = makeClient();
    CHECK_THROWS(client.get(url(port, "/x"), {}, /*retries=*/0));
    CHECK(server.requestsReceived() == 1);
  }
}

// ══════════════════════════════════════════════════════════════════════════
// T11: setReadMode(Sync)-failure -> not-sent classification. NO injection seam
//      exists (HttpClient::_transport is a private shared_ptr with no setter;
//      the only knob, transport allowReadModeSwitch, is not surfaced by
//      HttpClient and would disable switching globally, not inject one failure).
//      Searched: tests/ (no MockTransport / fault-inject for setReadMode),
//      HttpClient public surface (no setTransport), transport_types/transport.
//      COVERED BY INSPECTION: the setReadMode-failure throw (http_client.hpp,
//      the !setReadMode(Sync) branch in the pre-send try) sits INSIDE the same
//      pre-send try/catch as acquireConnection,
//      so it is rethrown as HttpRequestNotSentError exactly like a connect
//      failure -> classified not-sent -> retried. The connect-fail path through
//      that identical wrap IS exercised end-to-end by the connect-fail tests
//      above, so the shared classification mechanism is covered. (tracker T11)
// ══════════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════════
// T12: A successful POST with retries>0 still returns normally, reaching the
//      wire exactly once.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("successful POST with retries>0 sends once and returns 200",
          "[http_client_retry][post][success]")
{
  const std::uint16_t port = 18812;
  RawServer server;
  REQUIRE(server.start(port, okHandler()));

  HttpClient client = makeClient();

  auto resp = client.post(url(port, "/x"), "payload", {}, /*retries=*/2);
  CHECK(resp.statusCode == 200);
  CHECK(resp.body == "ok");
  CHECK(server.requestsReceived() == 1);
}
