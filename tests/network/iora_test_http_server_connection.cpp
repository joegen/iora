// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Server-side connection-management + response hardening (HTTP/WS family hardening
// Group 4). These tests drive a REAL HttpServer over a raw socket so they exercise
// the connection/keep-alive decision and the response serializer, not just the
// parser.
//   - SRV-M2: the request Connection header is parsed as a comma-separated token
//     list (RFC 9110 §7.6.1) — "keep-alive, close" / "close, foo" honor close.
//   - SRV-M3: the keep-alive decision is version-aware (RFC 9112 §9.3): an HTTP/1.0
//     request without "Connection: keep-alive" closes; an HTTP/1.1 request without
//     "Connection: close" persists.
//   - SRV-M5: multiple Set-Cookie values are emitted as SEPARATE field-lines
//     (RFC 6265 §3), never one comma-combined header.
//   - SRV-L2: a query name with no '=' ("?flag&x=1") is a parameter with an empty
//     value, not dropped (the bare-name -> empty-value rule is WHATWG-consistent).
//     Values are otherwise delivered RAW — NOT percent-decoded and '+' NOT converted
//     to space (pinned by the raw-value test); consistent decoding is tracked
//     separately (backlog 2026-09-12-6).

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
#include <vector>

using iora::network::HttpServer;

namespace
{
/// \brief Minimal raw HTTP/1.1 client that captures the FULL response head (so a
/// test can assert individual header field-lines, e.g. Connection and repeated
/// Set-Cookie) plus the Content-Length body, and can detect a subsequent close.
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

  /// \brief One response. `.status` is the status code (0 = no/short response =
  /// peer closed with nothing more). `.head` is the raw header block (no trailing
  /// CRLFCRLF). `.body` is the Content-Length body (empty if no CL).
  struct Resp
  {
    int status = 0;
    std::string head;
    std::string body;
  };

  Resp readResponse()
  {
    Resp r;
    std::size_t hdrEnd;
    while ((hdrEnd = _buf.find("\r\n\r\n")) == std::string::npos)
    {
      if (!fill())
      {
        return r;
      }
    }
    r.head = _buf.substr(0, hdrEnd);
    _buf.erase(0, hdrEnd + 4);

    {
      const std::size_t lineEnd = r.head.find("\r\n");
      std::string statusLine = (lineEnd == std::string::npos) ? r.head : r.head.substr(0, lineEnd);
      std::istringstream ss(statusLine);
      std::string ver;
      ss >> ver >> r.status;
    }

    const std::size_t cl = contentLength(r.head);
    if (cl != std::string::npos)
    {
      while (_buf.size() < cl)
      {
        if (!fill())
        {
          break;
        }
      }
      r.body = _buf.substr(0, std::min(cl, _buf.size()));
      _buf.erase(0, std::min(cl, _buf.size()));
    }
    return r;
  }

  /// \brief Count header field-lines whose name matches \p name (case-insensitive)
  /// in a response head. Used to assert Set-Cookie repetition.
  static int countHeader(const std::string &head, const std::string &name)
  {
    int count = 0;
    std::istringstream ss(head);
    std::string line;
    bool first = true;
    while (std::getline(ss, line))
    {
      if (!line.empty() && line.back() == '\r')
      {
        line.pop_back();
      }
      if (first)
      {
        first = false; // status line
        continue;
      }
      const std::size_t colon = line.find(':');
      if (colon == std::string::npos)
      {
        continue;
      }
      std::string key = line.substr(0, colon);
      if (iora::core::StringUtils::iequals(key, name))
      {
        ++count;
      }
    }
    return count;
  }

  /// \brief First value of the named header (case-insensitive), OWS-trimmed.
  static std::string headerValue(const std::string &head, const std::string &name)
  {
    std::istringstream ss(head);
    std::string line;
    bool first = true;
    while (std::getline(ss, line))
    {
      if (!line.empty() && line.back() == '\r')
      {
        line.pop_back();
      }
      if (first)
      {
        first = false;
        continue;
      }
      const std::size_t colon = line.find(':');
      if (colon == std::string::npos)
      {
        continue;
      }
      if (iora::core::StringUtils::iequals(line.substr(0, colon), name))
      {
        return std::string(iora::core::StringUtils::trim(line.substr(colon + 1)));
      }
    }
    return {};
  }

private:
  static std::size_t contentLength(const std::string &head)
  {
    std::istringstream ss(head);
    std::string line;
    while (std::getline(ss, line))
    {
      if (!line.empty() && line.back() == '\r')
      {
        line.pop_back();
      }
      const std::size_t colon = line.find(':');
      if (colon == std::string::npos)
      {
        continue;
      }
      if (iora::core::StringUtils::iequals(line.substr(0, colon), "Content-Length"))
      {
        const std::string v(iora::core::StringUtils::trim(line.substr(colon + 1)));
        try
        {
          return static_cast<std::size_t>(std::stoul(v));
        }
        catch (...)
        {
          return std::string::npos;
        }
      }
    }
    return std::string::npos;
  }

  bool fill()
  {
    char tmp[4096];
    ssize_t n = ::recv(_fd, tmp, sizeof(tmp), 0);
    if (n <= 0)
    {
      return false;
    }
    _buf.append(tmp, static_cast<std::size_t>(n));
    return true;
  }

  int _fd = -1;
  std::string _buf;
};

} // namespace

// ── SRV-M2: Connection is a comma-separated token list (RFC 9110 §7.6.1) ──────

TEST_CASE("HttpServer honors 'close' as a member of the Connection token list (SRV-M2)",
          "[http_server][connection]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<int> hits{0};
  srv.onGet("/a", [&hits](const HttpServer::Request &, HttpServer::Response &res)
            {
              hits.fetch_add(1);
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  // "keep-alive, close" — the OLD exact-match ("close") missed this and kept the
  // connection open; the token-list parse must honor the "close" member.
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive, close\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 200);
  REQUIRE(iora::core::StringUtils::iequals(Conn::headerValue(r.head, "Connection"), "close"));
  // Discriminator (avoids the recv-timeout ambiguity — a keep-alive idle read ALSO
  // times out to status 0): send a SECOND request. On the pre-fix (kept-open) code
  // the handler would run again and return 200; the fixed close path serves nothing.
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
  auto r2 = c.readResponse();
  REQUIRE(r2.status == 0);   // connection was closed; no second response
  REQUIRE(hits.load() == 1); // second request never dispatched
}

TEST_CASE("HttpServer keeps an HTTP/1.1 connection alive by default (SRV-M2 regression)",
          "[http_server][connection]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<int> hits{0};
  srv.onGet("/a", [&hits](const HttpServer::Request &, HttpServer::Response &res)
            {
              hits.fetch_add(1);
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  // No Connection header, HTTP/1.1 -> persistent. A second request on the SAME
  // connection must be served.
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
  auto r1 = c.readResponse();
  REQUIRE(r1.status == 200);
  REQUIRE(iora::core::StringUtils::iequals(Conn::headerValue(r1.head, "Connection"), "keep-alive"));
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  auto r2 = c.readResponse();
  REQUIRE(r2.status == 200);
  REQUIRE(hits.load() == 2);
}

// ── SRV-M3: version-aware persistence (RFC 9112 §9.3) ─────────────────────────

TEST_CASE("HttpServer closes an HTTP/1.0 connection with no keep-alive (SRV-M3)",
          "[http_server][connection]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<int> hits{0};
  srv.onGet("/a", [&hits](const HttpServer::Request &, HttpServer::Response &res)
            {
              hits.fetch_add(1);
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  // HTTP/1.0 + no Connection header -> non-persistent (RFC 9112 §9.3). The pre-fix
  // code never wrote httpVersion, so both close branches were dead and a 1.0 request
  // was wrongly kept alive: this asserts the connection now closes.
  c.sendRaw("GET /a HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 200);
  REQUIRE(iora::core::StringUtils::iequals(Conn::headerValue(r.head, "Connection"), "close"));
  // Discriminator (avoids recv-timeout ambiguity): a second request must NOT be
  // served. Pre-fix (wrongly kept-alive) it would return 200 and hits==2.
  c.sendRaw("GET /a HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
  auto r2 = c.readResponse();
  REQUIRE(r2.status == 0);
  REQUIRE(hits.load() == 1);
}

TEST_CASE("HttpServer keeps an HTTP/1.0 connection alive with Connection: keep-alive (SRV-M3)",
          "[http_server][connection]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<int> hits{0};
  srv.onGet("/a", [&hits](const HttpServer::Request &, HttpServer::Response &res)
            {
              hits.fetch_add(1);
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  // HTTP/1.0 + explicit keep-alive -> persistent. A second request must be served.
  c.sendRaw("GET /a HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n");
  auto r1 = c.readResponse();
  REQUIRE(r1.status == 200);
  REQUIRE(iora::core::StringUtils::iequals(Conn::headerValue(r1.head, "Connection"), "keep-alive"));
  c.sendRaw("GET /a HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  auto r2 = c.readResponse();
  REQUIRE(r2.status == 200);
  REQUIRE(hits.load() == 2);
}

// ── SRV-M5: repeated Set-Cookie field-lines (RFC 6265 §3) ─────────────────────

TEST_CASE("HttpServer emits multiple Set-Cookie values as separate field-lines (SRV-M5)",
          "[http_server][response][cookie]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  srv.onGet("/a", [](const HttpServer::Request &, HttpServer::Response &res)
            {
              res.add_cookie("sid=abc; Path=/; HttpOnly");
              res.add_cookie("csrf=xyz; Path=/; SameSite=Strict");
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 200);
  // Two DISTINCT Set-Cookie field-lines, not one comma-combined header. The single-
  // valued header map could carry at most one; this discriminates the vector path.
  REQUIRE(Conn::countHeader(r.head, "Set-Cookie") == 2);
  REQUIRE(r.head.find("sid=abc") != std::string::npos);
  REQUIRE(r.head.find("csrf=xyz") != std::string::npos);
}

TEST_CASE("HttpServer drops a Set-Cookie containing CRLF (SRV-M5 injection guard)",
          "[http_server][response][cookie]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  srv.onGet("/a", [](const HttpServer::Request &, HttpServer::Response &res)
            {
              res.add_cookie("ok=1; Path=/");
              res.add_cookie("evil=1\r\nX-Injected: yes"); // response-splitting attempt
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 200);
  REQUIRE(Conn::countHeader(r.head, "Set-Cookie") == 1);   // only the safe cookie
  REQUIRE(r.head.find("ok=1") != std::string::npos);
  REQUIRE(r.head.find("X-Injected") == std::string::npos); // no forged header on the wire
}

// ── SRV-L2: query name with no '=' is a parameter with an empty value ─────────

TEST_CASE("HttpServer keeps a bare query key with no '=' (SRV-L2)",
          "[http_server][query]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<bool> flagPresent{false};
  std::atomic<bool> flagEmpty{false};
  std::string xVal;
  srv.onGet("/a",
            [&](const HttpServer::Request &req, HttpServer::Response &res)
            {
              auto it = req.params.find("flag");
              flagPresent.store(it != req.params.end());
              flagEmpty.store(it != req.params.end() && it->second.empty());
              auto xit = req.params.find("x");
              xVal = (xit != req.params.end()) ? xit->second : std::string("<absent>");
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  // "?flag&x=1": the pre-fix parser dropped "flag" (no '='); it must now be present
  // with an empty value, and "x" must still parse to "1".
  c.sendRaw("GET /a?flag&x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 200);
  REQUIRE(flagPresent.load());
  REQUIRE(flagEmpty.load());
  REQUIRE(xVal == "1");
}

TEST_CASE("HttpServer honors 'close' as a non-first token 'close, foo' (SRV-M2)",
          "[http_server][connection]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<int> hits{0};
  srv.onGet("/a", [&hits](const HttpServer::Request &, HttpServer::Response &res)
            {
              hits.fetch_add(1);
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close, foo\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 200);
  REQUIRE(iora::core::StringUtils::iequals(Conn::headerValue(r.head, "Connection"), "close"));
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
  auto r2 = c.readResponse();
  REQUIRE(r2.status == 0);
  REQUIRE(hits.load() == 1);
}

TEST_CASE("HttpServer combines repeated Connection field-lines before token-scan (M1)",
          "[http_server][connection]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::atomic<int> hits{0};
  srv.onGet("/a", [&hits](const HttpServer::Request &, HttpServer::Response &res)
            {
              hits.fetch_add(1);
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  // "close" is on a SEPARATE field-line after "keep-alive". RFC 9110 §5.3 requires the
  // two lines be combined ("keep-alive, close") before token-scanning; last-wins would
  // drop "close" and wrongly keep the connection alive.
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 200);
  REQUIRE(iora::core::StringUtils::iequals(Conn::headerValue(r.head, "Connection"), "close"));
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
  auto r2 = c.readResponse();
  REQUIRE(r2.status == 0);
  REQUIRE(hits.load() == 1);
}

TEST_CASE("HttpServer query duplicate keys are last-wins (SRV-L2 documented limitation)",
          "[http_server][query]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::string aVal;
  srv.onGet("/a",
            [&](const HttpServer::Request &req, HttpServer::Response &res)
            {
              auto it = req.params.find("a");
              aVal = (it != req.params.end()) ? it->second : std::string("<absent>");
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  c.sendRaw("GET /a?a=1&a=2 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 200);
  REQUIRE(aVal == "2"); // last-wins (single-valued map; documented)
}

TEST_CASE("HttpServer delivers query values RAW / percent-undecoded (SRV-L2 documented)",
          "[http_server][query]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  std::string qVal;
  srv.onGet("/a",
            [&](const HttpServer::Request &req, HttpServer::Response &res)
            {
              auto it = req.params.find("q");
              qVal = (it != req.params.end()) ? it->second : std::string("<absent>");
              res.set_content("a", "text/plain");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  // Pins the CURRENT (documented) behavior: values are delivered raw — "%20" is not
  // percent-decoded and "+" is not converted to space. (Consistent URI decoding is
  // tracked as a separate item.)
  c.sendRaw("GET /a?q=a+b%20c HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 200);
  REQUIRE(qVal == "a+b%20c");
}

TEST_CASE("HttpServer emits Set-Cookie on a bodyless 204 response (SRV-M5)",
          "[http_server][response][cookie]")
{
  HttpServer srv;
  const int port = static_cast<int>(testnet::getFreePortTCP());
  srv.setPort(port);
  srv.onGet("/a", [](const HttpServer::Request &, HttpServer::Response &res)
            {
              res.status = 204;
              res.add_cookie("sid=abc; Path=/");
            });
  srv.start();

  Conn c;
  REQUIRE(c.open(port));
  c.sendRaw("GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
  auto r = c.readResponse();
  REQUIRE(r.status == 204);
  // Set-Cookie is not a body-framing header, so it survives the bodyless suppression.
  REQUIRE(Conn::countHeader(r.head, "Set-Cookie") == 1);
  REQUIRE(r.head.find("sid=abc") != std::string::npos);
  // ...and no body-framing header leaks onto the 204.
  REQUIRE(Conn::headerValue(r.head, "Content-Length").empty());
}
