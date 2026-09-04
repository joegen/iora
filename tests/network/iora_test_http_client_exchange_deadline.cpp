// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// HttpClient whole-exchange deadline (tracker 2026-07-26-10 task-1.10 /
// defect_14, a client-side slowloris bound). requestTimeout re-arms per
// receiveSync iteration, so a peer trickling one byte per window — or flooding
// well-formed interim 1xx responses — keeps a single request alive indefinitely.
// Config::totalRequestTimeout adds an outer deadline computed ONCE before
// connect; on expiry the attempt throws HttpExchangeDeadlineError, which is
// NON-retryable (an HttpFramingError), so total wall-clock stays ~1x the
// deadline instead of (retries+1)x. Zero disables it. A raw mock server
// controls the exact trickle/flood timing. Catch2 macros run on the MAIN thread
// only. Run under ASan (handle_segv=0); ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include "network/http_client_test_server.hpp"

#include <atomic>
#include <chrono>
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

// Server behaviors: TRICKLE (headers with a large Content-Length, then one body
// byte every ~120ms, never completing), FLOOD_1XX (a 100-continue every ~120ms,
// never a final response), FAST (an immediate 200).
enum class Mode { Trickle, Flood1xx, Fast };

class SlowServer
{
public:
  bool start(std::uint16_t port, Mode mode)
  {
    _mode = mode;
    _listenFd = makeListener(port);
    if (_listenFd < 0)
    {
      return false;
    }
    _thread = std::thread([this] { run(); });
    return true;
  }

  ~SlowServer() { shutdown(); }

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
  void drainRequest(int cs)
  {
    char buf[2048];
    std::string acc;
    for (int i = 0; i < 20 && acc.find("\r\n\r\n") == std::string::npos && !_stop.load(); ++i)
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
  }

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
      tv.tv_usec = 200 * 1000;
      ::setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      drainRequest(cs);

      if (_mode == Mode::Fast)
      {
        writeAll(cs, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
        ::close(cs);
        return;
      }
      if (_mode == Mode::Trickle)
      {
        // Declare 1000 bytes but trickle far fewer, so the body never completes.
        writeAll(cs, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n");
      }
      // Trickle body bytes / flood interim 1xx until the client gives up (send
      // fails) or we are told to stop. Capped so a bug cannot hang the suite.
      for (int i = 0; i < 200 && !_stop.load(); ++i)
      {
        std::string chunk = (_mode == Mode::Flood1xx) ? std::string("HTTP/1.1 100 Continue\r\n\r\n")
                                                       : std::string("x");
        ssize_t n = ::send(cs, chunk.data(), chunk.size(), MSG_NOSIGNAL);
        if (n <= 0)
        {
          break; // client closed (deadline tripped)
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
      }
      ::close(cs);
      return;
    }
  }

  int _listenFd{-1};
  std::thread _thread;
  std::atomic<bool> _stop{false};
  Mode _mode{Mode::Fast};
};

HttpClient::Config cfg(std::chrono::milliseconds deadline)
{
  HttpClient::Config c;
  c.requestTimeout = std::chrono::milliseconds(3000); // per-iteration, deliberately large
  c.connectTimeout = std::chrono::milliseconds(1000);
  c.reuseConnections = false;
  c.totalRequestTimeout = deadline;
  return c;
}

std::string urlFor(std::uint16_t port) { return "http://127.0.0.1:" + std::to_string(port) + "/x"; }

long elapsedMs(std::chrono::steady_clock::time_point start)
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                                               start)
    .count();
}

} // namespace

// HttpExchangeDeadlineError is NON-retryable: it must be an HttpFramingError so
// performRequest's HttpFramingError catch rejects it without retry.
TEST_CASE("HttpExchangeDeadlineError is a non-retryable HttpFramingError",
          "[http][deadline][defect_14]")
{
  static_assert(std::is_base_of<iora::network::HttpFramingError,
                                iora::network::HttpExchangeDeadlineError>::value,
                "deadline error must be a non-retryable HttpFramingError");
  SUCCEED();
}

// A trickle peer trips the deadline AT ~the configured value, long before the
// 3000ms per-iteration requestTimeout would.
TEST_CASE("A trickle peer trips the exchange deadline, not the per-iteration timeout",
          "[http][deadline][defect_14]")
{
  const std::uint16_t port = 19360;
  SlowServer server;
  REQUIRE(server.start(port, Mode::Trickle));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  HttpClient client(cfg(std::chrono::milliseconds(600)));
  auto start = std::chrono::steady_clock::now();
  CHECK_THROWS_AS(client.get(urlFor(port)), iora::network::HttpExchangeDeadlineError);
  const long ms = elapsedMs(start);
  CHECK(ms >= 500);  // not before the deadline
  CHECK(ms < 2000);  // and well before the 3000ms per-iteration requestTimeout

  server.shutdown();
}

// A well-formed interim-1xx flood also resets the per-iteration timer forever;
// the deadline is the only bound.
TEST_CASE("An interim-1xx flood is bounded by the exchange deadline",
          "[http][deadline][defect_14]")
{
  const std::uint16_t port = 19361;
  SlowServer server;
  REQUIRE(server.start(port, Mode::Flood1xx));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  HttpClient client(cfg(std::chrono::milliseconds(600)));
  auto start = std::chrono::steady_clock::now();
  CHECK_THROWS_AS(client.get(urlFor(port)), iora::network::HttpExchangeDeadlineError);
  CHECK(elapsedMs(start) < 2000);

  server.shutdown();
}

// The deadline is NON-retryable: an idempotent GET with retries=3 against a
// trickle peer must NOT multiply the wall-clock — total ~1x the deadline (plus
// the one connect), NOT (retries+1)x plus backoffs.
TEST_CASE("The exchange deadline is not retried on an idempotent method",
          "[http][deadline][defect_14]")
{
  const std::uint16_t port = 19362;
  SlowServer server;
  REQUIRE(server.start(port, Mode::Trickle));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  HttpClient client(cfg(std::chrono::milliseconds(500)));
  auto start = std::chrono::steady_clock::now();
  CHECK_THROWS_AS(client.get(urlFor(port), {}, /*retries=*/3),
                  iora::network::HttpExchangeDeadlineError);
  // If it were retried 4x with exponential backoff, this would be several
  // seconds; ~1x the 500ms deadline is well under 1800ms.
  CHECK(elapsedMs(start) < 1800);

  server.shutdown();
}

// A normal fast response is unaffected when a deadline is configured.
TEST_CASE("A fast response succeeds with a deadline configured",
          "[http][deadline][defect_14]")
{
  const std::uint16_t port = 19363;
  SlowServer server;
  REQUIRE(server.start(port, Mode::Fast));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  HttpClient client(cfg(std::chrono::milliseconds(1000)));
  auto r = client.get(urlFor(port));
  CHECK(r.statusCode == 200);

  server.shutdown();
}

// A zero deadline disables the bound: a fast request still works (the disabled
// path does not perturb normal requests). The unbounded property itself is not
// asserted here (it cannot be without waiting forever).
TEST_CASE("A zero deadline disables the bound without perturbing a normal request",
          "[http][deadline][defect_14]")
{
  const std::uint16_t port = 19364;
  SlowServer server;
  REQUIRE(server.start(port, Mode::Fast));
  std::this_thread::sleep_for(std::chrono::milliseconds(80));

  HttpClient client(cfg(std::chrono::milliseconds(0)));
  auto r = client.get(urlFor(port));
  CHECK(r.statusCode == 200);

  server.shutdown();
}
