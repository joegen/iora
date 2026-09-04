// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// HttpClient::postFile multipart hardening + postStream caller-override
// (tracker 2026-07-26-10 task-1.5 / defect_6 / defect_17). postFile interpolated
// the caller's fieldName/filename into the quoted-string part-headers with NO
// escaping (a CRLF injected part-headers, a quote broke the quoted-string), and
// built the boundary from a second-granularity, fully-predictable
// "----IoraBoundary<time>" that it never checked against the content. The fix
// REJECTS a quote/CR/LF/NUL in fieldName/filename (RFC 7578 §4.2 has no escaping
// spelling), and generates a high-entropy crypto::SecureRng boundary verified
// absent from the content (RFC 2046 §5.1.1). Separately postStream overwrote a
// caller-supplied Accept/Cache-Control; now it sets those only when absent.
// Catch2 macros run on the MAIN thread only; the server records under a mutex.
// Run under ASan (handle_segv=0); ctest -j1.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>

#include "network/http_client_test_server.hpp"
#include <iora/parsers/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
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

/// \brief One-shot raw server: captures the first request (headers + body) and
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

      // Read until we have the header block AND (if any) the full body, using a
      // Content-Length parse. Enough iterations to drain a small upload.
      std::string acc;
      char buf[4096];
      std::size_t expectedTotal = std::string::npos;
      for (int i = 0; i < 400; ++i)
      {
        if (expectedTotal != std::string::npos && acc.size() >= expectedTotal)
        {
          break;
        }
        ssize_t n = ::recv(cs, buf, sizeof(buf), 0);
        if (n > 0)
        {
          acc.append(buf, static_cast<std::size_t>(n));
          auto hdrEnd = acc.find("\r\n\r\n");
          if (expectedTotal == std::string::npos && hdrEnd != std::string::npos)
          {
            std::size_t clPos = acc.find("Content-Length:");
            if (clPos != std::string::npos && clPos < hdrEnd)
            {
              std::size_t vs = clPos + 15;
              while (vs < acc.size() && (acc[vs] == ' ' || acc[vs] == '\t'))
              {
                ++vs;
              }
              std::size_t ve = acc.find("\r\n", vs);
              std::size_t bodyLen = static_cast<std::size_t>(
                  std::stoul(acc.substr(vs, ve - vs)));
              expectedTotal = hdrEnd + 4 + bodyLen;
            }
            else
            {
              expectedTotal = hdrEnd + 4; // no body
            }
          }
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

std::string scratchDir()
{
  const char *base = std::getenv("TMPDIR");
  return std::string(base ? base : "/tmp");
}

/// \brief Write content to a file, return its path (or "" on failure).
std::string writeTempFile(const std::string &name, const std::string &content)
{
  const std::string path = scratchDir() + "/" + name;
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f)
  {
    return "";
  }
  f.write(content.data(), static_cast<std::streamsize>(content.size()));
  f.close();
  return path;
}

/// \brief Extract the boundary= value from a captured multipart Content-Type.
std::string boundaryOf(const std::string &req)
{
  const std::string key = "boundary=";
  auto p = req.find(key);
  if (p == std::string::npos)
  {
    return "";
  }
  p += key.size();
  auto e = req.find("\r\n", p);
  return req.substr(p, e - p);
}

} // namespace

// ---------------------------------------------------------------------------
// defect_6: postFile REJECTS injection in fieldName / filename.
// ---------------------------------------------------------------------------

TEST_CASE("postFile rejects a quote/CR/LF/NUL in fieldName",
          "[http][multipart][defect_6]")
{
  const std::string path = writeTempFile("iora_mp_ok.bin", "hello-bytes");
  REQUIRE_FALSE(path.empty());

  HttpClient client(cfg());
  const std::string deadUrl = "http://127.0.0.1:1/upload"; // no listener
  // The rejection happens in postFile BEFORE performRequest, so a dead port is
  // irrelevant — the throw type proves the guard fired, not a connect error.
  CHECK_THROWS_AS(client.postFile(deadUrl, "na\r\nme", path),
                  iora::network::HttpInvalidHeaderError);
  CHECK_THROWS_AS(client.postFile(deadUrl, "na\"me", path),
                  iora::network::HttpInvalidHeaderError);
  CHECK_THROWS_AS(client.postFile(deadUrl, std::string("na\x00me", 5), path),
                  iora::network::HttpInvalidHeaderError);
  CHECK_THROWS_AS(client.postFile(deadUrl, "na\rme", path),
                  iora::network::HttpInvalidHeaderError);
  std::remove(path.c_str());
}

TEST_CASE("postFile rejects a quote in the derived filename",
          "[http][multipart][defect_6]")
{
  // A basename containing a double-quote is a legal Unix filename; postFile
  // derives filename from the path and must reject it.
  const std::string path = writeTempFile("iora_mp_\"quote.bin", "data");
  REQUIRE_FALSE(path.empty());

  HttpClient client(cfg());
  CHECK_THROWS_AS(client.postFile("http://127.0.0.1:1/upload", "file", path),
                  iora::network::HttpInvalidHeaderError);
  std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// defect_17: high-entropy boundary, verified against the content, well-formed.
// ---------------------------------------------------------------------------

TEST_CASE("postFile uses a high-entropy, non-clock-derived boundary",
          "[http][multipart][defect_17]")
{
  const std::string path = writeTempFile("iora_mp_entropy.bin", "the file body");
  REQUIRE_FALSE(path.empty());

  const std::uint16_t port = 18221;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/upload";
  auto resp = client.postFile(url, "file", path);
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());

  const std::string boundary = boundaryOf(req);
  REQUIRE_FALSE(boundary.empty());
  // Prefix retained, followed by 36 hex chars of entropy (18 random bytes).
  CHECK(boundary.rfind("----IoraBoundary", 0) == 0);
  const std::string entropy = boundary.substr(std::string("----IoraBoundary").size());
  CHECK(entropy.size() == 36);
  for (char ch : entropy)
  {
    CHECK(((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')));
  }
  // Well-formed framing: opening + closing delimiter, disposition, body present.
  CHECK(req.find("--" + boundary + "\r\n") != std::string::npos);
  CHECK(req.find("\r\n--" + boundary + "--\r\n") != std::string::npos);
  CHECK(req.find("Content-Disposition: form-data; name=\"file\"; "
                 "filename=\"iora_mp_entropy.bin\"\r\n") != std::string::npos);
  CHECK(req.find("the file body") != std::string::npos);
  // The Content-Type carries this exact boundary (unconditional — it must match
  // the body delimiter, so a caller cannot override it).
  CHECK(req.find("Content-Type: multipart/form-data; boundary=" + boundary) !=
        std::string::npos);
  std::remove(path.c_str());
}

TEST_CASE("postFile boundaries differ across calls (not clock-derived)",
          "[http][multipart][defect_17]")
{
  const std::string path = writeTempFile("iora_mp_two.bin", "x");
  REQUIRE_FALSE(path.empty());

  auto grabBoundary = [&](std::uint16_t port) -> std::string
  {
    CapturingServer server;
    REQUIRE(server.start(port));
    HttpClient client(cfg());
    const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/upload";
    auto resp = client.postFile(url, "file", path);
    REQUIRE(resp.statusCode == 200);
    server.shutdown();
    return boundaryOf(server.capturedRequest());
  };

  // Two uploads within the same wall-clock second: a clock-derived boundary
  // would be identical; a random one differs.
  const std::string b1 = grabBoundary(18222);
  const std::string b2 = grabBoundary(18223);
  REQUIRE_FALSE(b1.empty());
  REQUIRE_FALSE(b2.empty());
  CHECK(b1 != b2);
  std::remove(path.c_str());
}

// NOTE (task-1.5 review, cpp17 L2): the RFC 2046 §5.1.1 non-appearance guard —
// the `while (fileContent.find(boundary) != npos) regenerate` loop — cannot be
// exercised deterministically (an 18-byte SecureRng collision is not forceable),
// so it is verified by inspection, not by a test case here.

// task-1.5 verification (cpp17 M2): postFile's generated Content-Type carries the
// boundary and MUST reach the wire UNCONDITIONALLY — a caller-supplied
// Content-Type must NOT override it (that would emit a boundary not matching the
// body delimiter -> unparseable multipart).
TEST_CASE("postFile ignores a caller-supplied Content-Type (boundary must match)",
          "[http][multipart][defect_6]")
{
  const std::string path = writeTempFile("iora_mp_ct.bin", "payload");
  REQUIRE_FALSE(path.empty());

  const std::uint16_t port = 18226;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/upload";
  auto resp = client.postFile(url, "file", path, {{"Content-Type", "text/plain"}});
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  const std::string boundary = boundaryOf(req);
  REQUIRE_FALSE(boundary.empty());
  // The generated multipart Content-Type wins; the caller's text/plain is gone,
  // and exactly one Content-Type line reaches the wire.
  CHECK(req.find("Content-Type: multipart/form-data; boundary=" + boundary) !=
        std::string::npos);
  CHECK(req.find("Content-Type: text/plain") == std::string::npos);
  std::remove(path.c_str());
}

// A MIXED-CASE caller key must not slip past the override either (the caller map
// is case-sensitive, so a naive operator[] would leave "content-type" live
// alongside the canonical "Content-Type" -> two lines, mis-framing the body).
// Round-2 review (cpp17 M-1 / web M2-1).
TEST_CASE("postFile ignores a mixed-case caller Content-Type (no duplicate line)",
          "[http][multipart][defect_6]")
{
  const std::string path = writeTempFile("iora_mp_ct2.bin", "payload");
  REQUIRE_FALSE(path.empty());

  const std::uint16_t port = 18227;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/upload";
  auto resp = client.postFile(url, "file", path, {{"content-type", "text/plain"}});
  REQUIRE(resp.statusCode == 200);

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  const std::string boundary = boundaryOf(req);
  REQUIRE_FALSE(boundary.empty());
  // The caller's text/plain value is gone entirely (erased ci), and the
  // generated multipart Content-Type is present.
  CHECK(req.find("text/plain") == std::string::npos);
  CHECK(req.find("boundary=" + boundary) != std::string::npos);
  // Exactly ONE request Content-Type line (the generated multipart one) reaches
  // the wire — no duplicate from the mixed-case caller key (web round-3 L1).
  // "multipart/form-data" is unique to the request Content-Type (the part header
  // is application/octet-stream), so counting it counts that line.
  std::size_t ctCount = 0;
  for (std::size_t p = req.find("multipart/form-data"); p != std::string::npos;
       p = req.find("multipart/form-data", p + 1))
  {
    ++ctCount;
  }
  CHECK(ctCount == 1);
  std::remove(path.c_str());
}

// ---------------------------------------------------------------------------
// defect_6: postStream SSE defaults are caller-OVERRIDABLE.
// ---------------------------------------------------------------------------

TEST_CASE("postStream sets Accept/Cache-Control defaults when the caller omits them",
          "[http][multipart][sse][defect_6]")
{
  const std::uint16_t port = 18224;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/sse";
  auto payload = iora::parsers::Json::object();
  client.postStream(url, payload, {}, [](const std::string &) {});

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  CHECK(req.find("Accept: text/event-stream\r\n") != std::string::npos);
  CHECK(req.find("Cache-Control: no-cache\r\n") != std::string::npos);
}

TEST_CASE("postStream lets a caller override Accept/Cache-Control",
          "[http][multipart][sse][defect_6]")
{
  const std::uint16_t port = 18225;
  CapturingServer server;
  REQUIRE(server.start(port));

  HttpClient client(cfg());
  const std::string url = "http://127.0.0.1:" + std::to_string(port) + "/sse";
  auto payload = iora::parsers::Json::object();
  client.postStream(url, payload,
                    {{"Accept", "application/custom"}, {"Cache-Control", "max-age=5"}},
                    [](const std::string &) {});

  server.shutdown();
  const std::string req = server.capturedRequest();
  REQUIRE_FALSE(req.empty());
  // The caller values survive; the library defaults are NOT emitted.
  CHECK(req.find("Accept: application/custom\r\n") != std::string::npos);
  CHECK(req.find("Cache-Control: max-age=5\r\n") != std::string::npos);
  CHECK(req.find("text/event-stream") == std::string::npos);
  CHECK(req.find("no-cache") == std::string::npos);
}
