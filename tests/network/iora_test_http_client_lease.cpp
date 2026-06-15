// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for the HttpClient exclusive per-connection lease: a SHARED HttpClient
// instance must be safe for concurrent same-host requests (serialized via the
// lease), with no request/response interleaving, no use-after-evict, no
// self-deadlock on retry, lease release on throw, and eviction on a server-sent
// "Connection: close". Tracker: 2026-06-06-1 (Approach A).
//
// Catch2 assertion macros are invoked ONLY on the main thread; worker threads
// record results into atomics / mutex-guarded containers and the main thread
// asserts after join(). Run under TSan (setarch -R) and ASan (handle_segv=0).

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>
#include <iora/network/webhook_server.hpp>

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace iora::network;

namespace
{

// ── Raw mock HTTP server ────────────────────────────────────────────────────
// A minimal listener that lets a test control the EXACT response bytes — needed
// to emit a server-sent "Connection: close" (which WebhookServer overwrites) or
// to close mid-exchange to force client failures.

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

// Read one request's headers (clientSock has a recv timeout set). Returns true
// if a full request header block arrived, false on timeout/close — lets a
// keep-alive handler loop serve multiple requests on one socket and stop when
// the client goes quiet.
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

/// \brief Per-connection handler: (clientSock, connectionIndex) -> writes reply.
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
        int idx = _accepted.fetch_add(1);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 300 * 1000;
        ::setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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
  RawHandler _handler;
};

std::string okResponse(const std::string &body, bool serverClose)
{
  std::string r = "HTTP/1.1 200 OK\r\n";
  r += "Content-Type: text/plain\r\n";
  r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  r += serverClose ? "Connection: close\r\n" : "Connection: keep-alive\r\n";
  r += "\r\n";
  r += body;
  return r;
}

// Build a 200 response with an explicit HTTP version and an exact "Connection"
// header line (verbatim — the test controls name case and token list). An empty
// connectionLine omits the Connection header entirely.
std::string customResponse(const std::string &httpVersion, const std::string &body,
                           const std::string &connectionLine)
{
  std::string r = "HTTP/" + httpVersion + " 200 OK\r\n";
  r += "Content-Type: text/plain\r\n";
  r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  if (!connectionLine.empty())
  {
    r += connectionLine + "\r\n";
  }
  r += "\r\n";
  r += body;
  return r;
}

// A handler that serves multiple requests on ONE socket (persistent/keep-alive),
// replying with a fixed response each time, until the client goes quiet. Used to
// assert connection REUSE (acceptedCount stays 1).
RawHandler keepAliveHandler(std::string response)
{
  return [response](int clientSock, int /*idx*/)
  {
    while (readRequest(clientSock))
    {
      writeAll(clientSock, response);
    }
  };
}

// Spin until \p flag is set or the deadline elapses. Returns the flag's final
// value so the caller can REQUIRE it (a stuck request surfaces as an assertion
// failure rather than an indefinite hang).
bool waitForFlag(const std::atomic<bool> &flag, std::chrono::milliseconds timeout)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!flag.load())
  {
    if (std::chrono::steady_clock::now() >= deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return true;
}

// ── WebhookServer fixture (real server for echo / slow / simple endpoints) ───

class LeaseTestFixture
{
public:
  explicit LeaseTestFixture(std::uint16_t port) : _port(port)
  {
    server.setPort(port);
    server.onPost("/echo",
                  [](const WebhookServer::Request &req, WebhookServer::Response &res)
                  {
                    res.set_content(req.body, "text/plain");
                    res.status = 200;
                  });
    server.onGet("/simple",
                 [](const WebhookServer::Request &, WebhookServer::Response &res)
                 {
                   res.set_content("ok", "text/plain");
                   res.status = 200;
                 });
    server.onGet("/slow",
                 [](const WebhookServer::Request &, WebhookServer::Response &res)
                 {
                   std::this_thread::sleep_for(std::chrono::milliseconds(500));
                   res.set_content("slow", "text/plain");
                   res.status = 200;
                 });
    // Long-held endpoint for lease-contention tests: signals when the request
    // has reached the server (so the caller provably holds the lease and is
    // mid-exchange), then holds the connection for a wide window.
    server.onGet("/hold",
                 [this](const WebhookServer::Request &, WebhookServer::Response &res)
                 {
                   holdEndpointEntered.store(true);
                   std::this_thread::sleep_for(std::chrono::milliseconds(1500));
                   res.set_content("held", "text/plain");
                   res.status = 200;
                 });
    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
  }

  ~LeaseTestFixture() { server.stop(); }

  std::string url(const std::string &path) const
  {
    return "http://127.0.0.1:" + std::to_string(_port) + path;
  }

  WebhookServer server;
  std::atomic<bool> holdEndpointEntered{false};

private:
  std::uint16_t _port;
};

} // namespace

// ══════════════════════════════════════════════════════════════════════════
// (a) No interleaving/stealing: concurrent same-host requests on ONE shared
//     client each get back their own response body.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: concurrent same-host requests do not interleave",
          "[http_client_lease][concurrent]")
{
  LeaseTestFixture fixture(8087);
  HttpClient client; // shared across all threads; reuseConnections = true (default)

  const int numThreads = 8;
  const int perThread = 25;
  std::atomic<int> success{0};
  std::atomic<int> mismatch{0};
  std::atomic<int> exceptions{0};

  std::vector<std::thread> threads;
  for (int t = 0; t < numThreads; ++t)
  {
    threads.emplace_back(
      [&, t]()
      {
        for (int j = 0; j < perThread; ++j)
        {
          std::string body = "thread-" + std::to_string(t) + "-req-" + std::to_string(j) +
                             "-payload-" + std::to_string(t * 100000 + j);
          try
          {
            auto resp = client.post(fixture.url("/echo"), body);
            if (resp.statusCode == 200 && resp.body == body)
            {
              success.fetch_add(1);
            }
            else
            {
              mismatch.fetch_add(1);
            }
          }
          catch (...)
          {
            exceptions.fetch_add(1);
          }
        }
      });
  }
  for (auto &th : threads)
  {
    th.join();
  }

  REQUIRE(exceptions.load() == 0);
  REQUIRE(mismatch.load() == 0);
  REQUIRE(success.load() == numThreads * perThread);
}

// ══════════════════════════════════════════════════════════════════════════
// (b) No use-after-evict: reuseConnections=false forces drop+reconnect on every
//     request; heavy same-host concurrency exercises eviction under the lease.
//     Correctness (bodies match) plus TSan/ASan cleanliness validate no UAF.
//
//     NOTE on the original hazard (one thread's dropConnection closing a session
//     another thread is mid-receiveSync on): under the lease this is STRUCTURALLY
//     UNREACHABLE. dropConnection for a host:port is only ever called by the
//     thread that holds that host's lease (from inside executeRequest), and the
//     lease guarantees exactly one such thread per host:port at a time. No other
//     thread can be mid-receiveSync on the same session because it cannot hold
//     the lease. This test exercises the drop+reconnect churn under contention;
//     the cross-session-teardown race is eliminated by construction, not merely
//     untriggered here.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: drop-and-reconnect under contention is safe",
          "[http_client_lease][evict]")
{
  LeaseTestFixture fixture(8088);
  HttpClient::Config config;
  config.reuseConnections = false; // every exchange evicts the connection
  HttpClient client(config);

  const int numThreads = 6;
  const int perThread = 15;
  std::atomic<int> success{0};
  std::atomic<int> mismatch{0};
  std::atomic<int> exceptions{0};

  std::vector<std::thread> threads;
  for (int t = 0; t < numThreads; ++t)
  {
    threads.emplace_back(
      [&, t]()
      {
        for (int j = 0; j < perThread; ++j)
        {
          std::string body = "evict-" + std::to_string(t) + "-" + std::to_string(j);
          try
          {
            auto resp = client.post(fixture.url("/echo"), body);
            if (resp.statusCode == 200 && resp.body == body)
            {
              success.fetch_add(1);
            }
            else
            {
              mismatch.fetch_add(1);
            }
          }
          catch (...)
          {
            exceptions.fetch_add(1);
          }
        }
      });
  }
  for (auto &th : threads)
  {
    th.join();
  }

  REQUIRE(exceptions.load() == 0);
  REQUIRE(mismatch.load() == 0);
  REQUIRE(success.load() == numThreads * perThread);
}

// ══════════════════════════════════════════════════════════════════════════
// (e) / DD-A9: a server-sent "Connection: close" (while the client requested
//     keep-alive) evicts the cached connection, so the next same-host request
//     opens a FRESH connection rather than reusing a dead socket.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: honors server-sent Connection: close (DD-A9)",
          "[http_client_lease][server_close]")
{
  const std::uint16_t port = 18950;
  RawServer raw;
  REQUIRE(raw.start(port,
                    [](int clientSock, int /*idx*/)
                    {
                      readRequest(clientSock);
                      writeAll(clientSock, okResponse("hello", /*serverClose=*/true));
                    }));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  HttpClient::Config config;
  config.reuseConnections = true; // client WANTS keep-alive; server overrides
  config.requestTimeout = std::chrono::milliseconds(1000);
  HttpClient client(config);

  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/x";

  auto r1 = client.get(url); // retries default 0
  REQUIRE(r1.statusCode == 200);
  REQUIRE(r1.body == "hello");

  // If the server-close were ignored, the client would reuse the now-dead socket
  // and this second request would fail. Eviction makes it reconnect instead.
  auto r2 = client.get(url);
  REQUIRE(r2.statusCode == 200);
  REQUIRE(r2.body == "hello");

  REQUIRE(raw.acceptedCount() == 2); // two distinct connections => evicted+reconnected
  raw.shutdown();
}

// ══════════════════════════════════════════════════════════════════════════
// DD-A9 / C-1: the response Connection header is matched case-INSENSITIVELY on
//     the field NAME (RFC 7230 §3.2). A lowercase "connection: close" must still
//     evict — a case-sensitive lookup would silently miss it and reuse a dead
//     socket against the many real servers/proxies that lowercase header names.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: honors lowercase 'connection: close' header name",
          "[http_client_lease][server_close][case_insensitive]")
{
  const std::uint16_t port = 18955;
  RawServer raw;
  REQUIRE(raw.start(port,
                    [](int clientSock, int /*idx*/)
                    {
                      readRequest(clientSock);
                      // Lowercase field name + mixed-case value.
                      writeAll(clientSock,
                               customResponse("1.1", "hello", "connection: Close"));
                    }));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  HttpClient::Config config;
  config.reuseConnections = true;
  config.requestTimeout = std::chrono::milliseconds(1000);
  HttpClient client(config);
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/x";

  REQUIRE(client.get(url).body == "hello");
  REQUIRE(client.get(url).body == "hello");
  REQUIRE(raw.acceptedCount() == 2); // evicted on lowercase close => reconnected
  raw.shutdown();
}

// ══════════════════════════════════════════════════════════════════════════
// DD-A9 / H-1: the Connection header is a comma-separated TOKEN list (RFC 7230
//     §6.1). A token that merely CONTAINS "close" as a substring (e.g.
//     "X-Close-Hint") must NOT be treated as a close signal — the connection is
//     kept alive and reused (acceptedCount stays 1).
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: multi-token Connection without a close token is reused",
          "[http_client_lease][server_close][tokenize]")
{
  const std::uint16_t port = 18956;
  RawServer raw;
  REQUIRE(raw.start(port, keepAliveHandler(
                            customResponse("1.1", "kept", "Connection: keep-alive, X-Close-Hint"))));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  HttpClient::Config config;
  config.reuseConnections = true;
  config.requestTimeout = std::chrono::milliseconds(1000);
  HttpClient client(config);
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/x";

  REQUIRE(client.get(url).body == "kept");
  REQUIRE(client.get(url).body == "kept");
  REQUIRE(raw.acceptedCount() == 1); // substring "close" must NOT evict => reused
  raw.shutdown();
}

// ══════════════════════════════════════════════════════════════════════════
// DD-A9 / M-1: version-default persistence (RFC 7230 §6.3). An HTTP/1.0 response
//     with NO Connection header defaults to close (evict + reconnect); an
//     HTTP/1.0 response WITH "Connection: keep-alive" is persistent (reused).
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: HTTP/1.0 response without keep-alive evicts",
          "[http_client_lease][server_close][http10]")
{
  const std::uint16_t port = 18957;
  RawServer raw;
  REQUIRE(raw.start(port,
                    [](int clientSock, int /*idx*/)
                    {
                      readRequest(clientSock);
                      writeAll(clientSock, customResponse("1.0", "v10", /*connectionLine=*/""));
                    }));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  HttpClient::Config config;
  config.reuseConnections = true;
  config.requestTimeout = std::chrono::milliseconds(1000);
  HttpClient client(config);
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/x";

  REQUIRE(client.get(url).body == "v10");
  REQUIRE(client.get(url).body == "v10");
  REQUIRE(raw.acceptedCount() == 2); // HTTP/1.0 default close => reconnected
  raw.shutdown();
}

TEST_CASE("Shared HttpClient: HTTP/1.0 response with keep-alive is reused",
          "[http_client_lease][server_close][http10]")
{
  const std::uint16_t port = 18958;
  RawServer raw;
  REQUIRE(raw.start(port,
                    keepAliveHandler(customResponse("1.0", "v10ka", "Connection: keep-alive"))));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  HttpClient::Config config;
  config.reuseConnections = true;
  config.requestTimeout = std::chrono::milliseconds(1000);
  HttpClient client(config);
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/x";

  REQUIRE(client.get(url).body == "v10ka");
  REQUIRE(client.get(url).body == "v10ka");
  REQUIRE(raw.acceptedCount() == 1); // explicit keep-alive overrides 1.0 default => reused
  raw.shutdown();
}

// A "close" token anywhere in the list wins over "keep-alive" (RFC 7230 §6.1).
TEST_CASE("Shared HttpClient: 'keep-alive, close' token list evicts",
          "[http_client_lease][server_close][tokenize]")
{
  const std::uint16_t port = 18959;
  RawServer raw;
  REQUIRE(raw.start(port,
                    [](int clientSock, int /*idx*/)
                    {
                      readRequest(clientSock);
                      writeAll(clientSock,
                               customResponse("1.1", "tl", "Connection: keep-alive, close"));
                    }));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  HttpClient::Config config;
  config.reuseConnections = true;
  config.requestTimeout = std::chrono::milliseconds(1000);
  HttpClient client(config);
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/x";

  REQUIRE(client.get(url).body == "tl");
  REQUIRE(client.get(url).body == "tl");
  REQUIRE(raw.acceptedCount() == 2); // close token wins => evicted+reconnected
  raw.shutdown();
}

// HTTP/1.0 with an explicit "Connection: close" evicts (belt-and-suspenders over
// the 1.0 version default).
TEST_CASE("Shared HttpClient: HTTP/1.0 response with explicit close evicts",
          "[http_client_lease][server_close][http10]")
{
  const std::uint16_t port = 18960;
  RawServer raw;
  REQUIRE(raw.start(port,
                    [](int clientSock, int /*idx*/)
                    {
                      readRequest(clientSock);
                      writeAll(clientSock, customResponse("1.0", "v10c", "Connection: close"));
                    }));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  HttpClient::Config config;
  config.reuseConnections = true;
  config.requestTimeout = std::chrono::milliseconds(1000);
  HttpClient client(config);
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/x";

  REQUIRE(client.get(url).body == "v10c");
  REQUIRE(client.get(url).body == "v10c");
  REQUIRE(raw.acceptedCount() == 2);
  raw.shutdown();
}

// ══════════════════════════════════════════════════════════════════════════
// (b, large bodies): same-host concurrency with reuseConnections=false and
//     multi-KB DISTINCT bodies (larger than one TCP segment) — exercises
//     multi-recv reassembly under the lease with drop-and-reconnect churn, with
//     no keep-alive reuse. Any byte-interleaving/stealing would corrupt a body.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: large bodies do not interleave (no keep-alive)",
          "[http_client_lease][evict][large_body]")
{
  LeaseTestFixture fixture(8093);
  HttpClient::Config config;
  config.reuseConnections = false; // drop + reconnect every request
  config.requestTimeout = std::chrono::milliseconds(3000);
  HttpClient client(config);

  const int numThreads = 6;
  const int perThread = 8;
  std::atomic<int> success{0};
  std::atomic<int> mismatch{0};
  std::atomic<int> exceptions{0};

  std::vector<std::thread> threads;
  for (int t = 0; t < numThreads; ++t)
  {
    threads.emplace_back(
      [&, t]()
      {
        for (int j = 0; j < perThread; ++j)
        {
          // ~16KB body, unique per (thread,request), filled with a per-request
          // byte so any cross-request interleave is detectable.
          char fill = static_cast<char>('A' + ((t * perThread + j) % 26));
          std::string body(16000, fill);
          body += "-t" + std::to_string(t) + "-j" + std::to_string(j);
          try
          {
            auto resp = client.post(fixture.url("/echo"), body);
            if (resp.statusCode == 200 && resp.body == body)
            {
              success.fetch_add(1);
            }
            else
            {
              mismatch.fetch_add(1);
            }
          }
          catch (...)
          {
            exceptions.fetch_add(1);
          }
        }
      });
  }
  for (auto &th : threads)
  {
    th.join();
  }

  REQUIRE(exceptions.load() == 0);
  REQUIRE(mismatch.load() == 0);
  REQUIRE(success.load() == numThreads * perThread);
}

// ══════════════════════════════════════════════════════════════════════════
// (d) Lease released on a throwing request: the first request fails (server
//     closes without responding), and a SUBSEQUENT same-host request succeeds —
//     proving the lease was released on the exception path (RAII).
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: lease released when a request throws",
          "[http_client_lease][throw_release]")
{
  const std::uint16_t port = 18951;
  RawServer raw;
  REQUIRE(raw.start(port,
                    [](int clientSock, int idx)
                    {
                      readRequest(clientSock);
                      if (idx == 0)
                      {
                        // First connection: close immediately, no response.
                        return;
                      }
                      writeAll(clientSock, okResponse("recovered", /*serverClose=*/false));
                    }));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  HttpClient::Config config;
  config.requestTimeout = std::chrono::milliseconds(800);
  // Finite lease timeout: a leaked lease would surface as a timeout (test fails)
  // rather than an infinite hang.
  config.leaseAcquireTimeout = std::chrono::milliseconds(2000);
  HttpClient client(config);

  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/y";

  bool firstThrew = false;
  try
  {
    client.get(url);
  }
  catch (const std::exception &)
  {
    firstThrew = true;
  }
  REQUIRE(firstThrew);

  // Same host:port — only reachable if the lease from the failed request was
  // released.
  auto r2 = client.get(url);
  REQUIRE(r2.statusCode == 200);
  REQUIRE(r2.body == "recovered");

  raw.shutdown();
}

// ══════════════════════════════════════════════════════════════════════════
// (c) / DD-A7: retries under same-host contention never self-deadlock. The
//     server fails every connection; each thread retries; all threads complete.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: retries under contention do not deadlock",
          "[http_client_lease][retry]")
{
  const std::uint16_t port = 18952;
  RawServer raw;
  REQUIRE(raw.start(port,
                    [](int clientSock, int /*idx*/)
                    {
                      readRequest(clientSock);
                      // Always close without a valid response -> client fails.
                    }));
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  HttpClient::Config config;
  config.requestTimeout = std::chrono::milliseconds(400);
  // A hypothetical self-deadlock would surface as a bounded timeout, not a hang.
  config.leaseAcquireTimeout = std::chrono::milliseconds(3000);
  HttpClient client(config);

  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/z";
  const int numThreads = 6;
  std::atomic<int> completed{0};

  std::vector<std::thread> threads;
  for (int t = 0; t < numThreads; ++t)
  {
    threads.emplace_back(
      [&]()
      {
        try
        {
          client.get(url, {}, /*retries=*/1);
        }
        catch (...)
        {
          // expected: server never responds
        }
        completed.fetch_add(1);
      });
  }
  for (auto &th : threads)
  {
    th.join();
  }

  REQUIRE(completed.load() == numThreads); // reaching here == no deadlock
  raw.shutdown();
}

// ══════════════════════════════════════════════════════════════════════════
// DD-A5: a bounded leaseAcquireTimeout surfaces a DISTINCT timeout error when a
//     same-host request cannot acquire the lease in time.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: bounded lease-acquire timeout", "[http_client_lease][lease_timeout]")
{
  LeaseTestFixture fixture(8089);
  HttpClient::Config config;
  config.requestTimeout = std::chrono::milliseconds(3000);
  config.leaseAcquireTimeout = std::chrono::milliseconds(150);
  HttpClient client(config);

  // Holder thread occupies the lease via a long (~1500ms) /hold request.
  std::thread holder([&]() {
    try
    {
      client.get(fixture.url("/hold"));
    }
    catch (...)
    {
    }
  });

  // Deterministic: the holder provably holds the lease once its request has
  // reached the server handler (no who-wins-the-lease race).
  REQUIRE(waitForFlag(fixture.holdEndpointEntered, std::chrono::seconds(5)));

  std::string errMsg;
  bool threw = false;
  auto start = std::chrono::steady_clock::now();
  try
  {
    client.get(fixture.url("/hold")); // same host:port -> blocks, then times out
  }
  catch (const std::exception &e)
  {
    threw = true;
    errMsg = e.what();
  }
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now() - start);

  holder.join();

  REQUIRE(threw);
  REQUIRE(errMsg.find("lease") != std::string::npos);
  // Bounded near leaseAcquireTimeout (150ms), well under the holder's 1500ms hold.
  REQUIRE(elapsed.count() < 600);
}

// ══════════════════════════════════════════════════════════════════════════
// DD-A8: cleanup() wakes a thread blocked in acquireLease (indefinite wait) so
//     a shutdown during a contended wait fails fast instead of deadlocking.
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: cleanup wakes blocked lease waiter (DD-A8)",
          "[http_client_lease][shutdown]")
{
  LeaseTestFixture fixture(8090);
  HttpClient::Config config;
  config.requestTimeout = std::chrono::milliseconds(3000);
  config.leaseAcquireTimeout = std::chrono::milliseconds(0); // indefinite wait
  HttpClient client(config);

  std::thread holder([&]() {
    try
    {
      client.get(fixture.url("/hold")); // holds the lease ~1500ms
    }
    catch (...)
    {
    }
  });
  // Wait until the holder provably holds the lease (request reached the server).
  REQUIRE(waitForFlag(fixture.holdEndpointEntered, std::chrono::seconds(5)));

  std::atomic<bool> waiterStarted{false};
  std::atomic<bool> waiterDone{false};
  std::atomic<bool> waiterThrew{false};
  std::thread waiter([&]() {
    waiterStarted.store(true);
    try
    {
      client.get(fixture.url("/simple")); // same host -> blocks indefinitely
    }
    catch (...)
    {
      waiterThrew.store(true);
    }
    waiterDone.store(true);
  });

  REQUIRE(waitForFlag(waiterStarted, std::chrono::seconds(5)));
  std::this_thread::sleep_for(std::chrono::milliseconds(200)); // ensure waiter parked in the wait
  client.cleanup();                                            // must wake the waiter

  holder.join();
  waiter.join();

  REQUIRE(waiterDone.load());  // did not hang
  REQUIRE(waiterThrew.load()); // shutdown surfaced as an exception
}

// ══════════════════════════════════════════════════════════════════════════
// Value proposition: requests to DIFFERENT hosts run CONCURRENTLY (the lease
//     serializes only same-host work).
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("Shared HttpClient: different hosts are not serialized",
          "[http_client_lease][concurrent_hosts]")
{
  LeaseTestFixture fixtureA(8091);
  LeaseTestFixture fixtureB(8092);
  HttpClient::Config config;
  config.requestTimeout = std::chrono::milliseconds(2000);
  HttpClient client(config);

  std::atomic<int> ok{0};
  auto start = std::chrono::steady_clock::now();

  std::thread a([&]() {
    try
    {
      if (client.get(fixtureA.url("/slow")).statusCode == 200)
      {
        ok.fetch_add(1);
      }
    }
    catch (...)
    {
    }
  });
  std::thread b([&]() {
    try
    {
      if (client.get(fixtureB.url("/slow")).statusCode == 200)
      {
        ok.fetch_add(1);
      }
    }
    catch (...)
    {
    }
  });
  a.join();
  b.join();

  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::steady_clock::now() - start);

  REQUIRE(ok.load() == 2);
  // Two ~500ms requests to different hosts; if serialized this would be ~1000ms.
  REQUIRE(elapsed.count() < 850);
}
