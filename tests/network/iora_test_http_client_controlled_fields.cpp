// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// HttpClient rejects/deduplicates the request header fields it controls itself
// (tracker 2026-07-26-10 task-1.3 / defect_2 / defect_4). executeRequest emits
// its own Host, Connection and Content-Length; a caller supplying any of them —
// or Transfer-Encoding/TE/Trailer/Upgrade/Expect — produced a duplicate or
// conflicting framing field (CL/CL and TE.CL request smuggling). The fix throws
// HttpInvalidHeaderError (a non-retryable HttpFramingError) for those names,
// matched case-insensitively, BEFORE any connect; User-Agent stays
// caller-OVERRIDABLE (the library default is emitted only when the caller
// supplied none). The pure predicate isFramingControlledHeaderName is unit-
// tested without a socket; a capturing server confirms the wire carries exactly
// one of each controlled line. Catch2 macros run on the MAIN thread only; the
// server records under a mutex. Run under ASan (handle_segv=0); ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include "network/http_client_test_server.hpp"

#include <atomic>
#include <cctype>
#include <chrono>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
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

/// \brief Count case-insensitive occurrences of a "Name:" field line at the
/// start of a line in the captured request block.
int countFieldLines(const std::string &req, const std::string &name)
{
  const std::string needle = name + ":";
  int count = 0;
  std::size_t pos = 0;
  // Field lines start at a line boundary — either the very start or after CRLF.
  while ((pos = req.find("\r\n", pos)) != std::string::npos)
  {
    std::size_t lineStart = pos + 2;
    if (lineStart + needle.size() <= req.size() &&
        iora::network::ciEqualsAscii(req.substr(lineStart, needle.size()), needle))
    {
      ++count;
    }
    pos += 2;
  }
  // Also check the very first line (the request-line is first, so a field never
  // begins at offset 0 — but guard for completeness).
  if (req.size() >= needle.size() &&
      iora::network::ciEqualsAscii(req.substr(0, needle.size()), needle))
  {
    ++count;
  }
  return count;
}

} // namespace

// ---------------------------------------------------------------------------
// Socket-free unit test of the controlled-name predicate (task-1.3).
// ---------------------------------------------------------------------------

TEST_CASE("isFramingControlledHeaderName matches the controlled set case-insensitively",
          "[http][controlled][defect_2][defect_4]")
{
  using iora::network::isFramingControlledHeaderName;
  // Every controlled name, in canonical, lower and upper case.
  for (const std::string base :
       {"Host", "Content-Length", "Connection", "Transfer-Encoding", "TE",
        "Trailer", "Upgrade", "Expect"})
  {
    CAPTURE(base);
    CHECK(isFramingControlledHeaderName(base));
    std::string lower = base, upper = base;
    for (char &ch : lower)
    {
      ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    for (char &ch : upper)
    {
      ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    CHECK(isFramingControlledHeaderName(lower));
    CHECK(isFramingControlledHeaderName(upper));
  }
  // Mixed case still matches (the desync-reinstating bypass this closes).
  CHECK(isFramingControlledHeaderName("content-LENGTH"));
  CHECK(isFramingControlledHeaderName("TrAnSfEr-EnCoDiNg"));

  // NOT controlled: content-coding (JsonRpcClient self-injects it — FLAG-1),
  // User-Agent (caller-overridable), ordinary custom headers.
  CHECK_FALSE(isFramingControlledHeaderName("Content-Encoding"));
  CHECK_FALSE(isFramingControlledHeaderName("content-encoding"));
  CHECK_FALSE(isFramingControlledHeaderName("Accept-Encoding"));
  CHECK_FALSE(isFramingControlledHeaderName("User-Agent"));
  CHECK_FALSE(isFramingControlledHeaderName("X-Foo"));
  CHECK_FALSE(isFramingControlledHeaderName("Content-Type"));
  CHECK_FALSE(isFramingControlledHeaderName(""));
}

// ---------------------------------------------------------------------------
// Wire behavior: a controlled caller header throws before connect.
// ---------------------------------------------------------------------------

// The URL points at a port with NO listener: if the guard were removed,
// executeRequest would proceed to connect and surface a connect/not-sent error
// instead — so getting HttpInvalidHeaderError proves the throw precedes any
// connect. Mixed-case entries are the load-bearing mutation cases.
TEST_CASE("A controlled caller header throws before connect",
          "[http][controlled][defect_2][defect_4]")
{
  HttpClient client(cfg());
  const std::string deadUrl = "http://127.0.0.1:1/rpc"; // port 1: no listener
  for (const std::string name :
       {"Host", "Content-Length", "Connection", "Transfer-Encoding", "TE",
        "Trailer", "Upgrade", "Expect",
        // Mixed case must NOT bypass the guard.
        "content-length", "TRANSFER-ENCODING", "hOsT", "connECTION",
        "expect"})
  {
    CAPTURE(name);
    CHECK_THROWS_AS(client.get(deadUrl, {{name, "x"}}),
                    iora::network::HttpInvalidHeaderError);
  }
}

// Content-Encoding / Accept-Encoding are NOT rejected (task-1.1 FLAG-1: JSON-RPC
// request-gzip self-injects Content-Encoding). They must flow to the wire.
TEST_CASE("Content-Encoding is NOT rejected and reaches the wire",
          "[http][controlled][flag1]")
{
  const std::uint16_t port = 18211;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/rpc";
  auto resp = client.post(url, "payload", {{"Content-Encoding", "gzip"}});
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  CHECK(req.find("Content-Encoding: gzip\r\n") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Wire behavior: exactly one of each controlled line HttpClient emits.
// ---------------------------------------------------------------------------

TEST_CASE("The wire carries exactly one Host, Connection and Content-Length",
          "[http][controlled][defect_2]")
{
  const std::uint16_t port = 18212;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/rpc";
  auto resp = client.post(url, "hello", {{"X-Foo", "bar"}});
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  CHECK(countFieldLines(req, "Host") == 1);
  CHECK(countFieldLines(req, "Connection") == 1);
  CHECK(countFieldLines(req, "Content-Length") == 1);
  CHECK(countFieldLines(req, "User-Agent") == 1);
  CHECK(req.find("X-Foo: bar\r\n") != std::string::npos);
  // The single Content-Length reflects the body length.
  CHECK(req.find("Content-Length: 5\r\n") != std::string::npos);
}

// ---------------------------------------------------------------------------
// User-Agent is caller-OVERRIDABLE: exactly one line, the caller's value.
// ---------------------------------------------------------------------------

TEST_CASE("A caller User-Agent overrides the library default (one line)",
          "[http][controlled][user-agent]")
{
  const std::uint16_t port = 18213;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/rpc";
  auto resp = client.get(url, {{"User-Agent", "my-agent/9"}});
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  // Exactly one User-Agent line, and it is the caller's — the library default
  // was suppressed (no duplicate).
  CHECK(countFieldLines(req, "User-Agent") == 1);
  CHECK(req.find("User-Agent: my-agent/9\r\n") != std::string::npos);
}

// A mixed-case caller User-Agent still overrides (one line), proving the
// suppression check is case-insensitive too.
TEST_CASE("A mixed-case caller User-Agent still overrides",
          "[http][controlled][user-agent]")
{
  const std::uint16_t port = 18214;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/rpc";
  auto resp = client.get(url, {{"user-AGENT", "mixed/1"}});
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  CHECK(countFieldLines(req, "User-Agent") == 1);
  CHECK(req.find("user-AGENT: mixed/1\r\n") != std::string::npos);
}
