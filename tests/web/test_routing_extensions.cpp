// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit/integration tests for the iora HttpServer routing extension
// (network/http_server.hpp): pattern routing (exact / named-segment /
// trailing-wildcard), _mutex narrowing, SSE response-suppression primitives,
// auto HEAD/OPTIONS, OPTIONS *, getStatusText 304/426, and the shutdown /
// recursive-lock concurrency fixes.
//
// Tracker: tasks/iora/ongoing/2026-05-29-4_htmx-support_phase3_routing-extension_P2.json
// Architecture (source of truth): architecture/iora/routing_extension.json
//
// Registered via the WEB_TESTS set in tests/CMakeLists.txt; build with
// -DIORA_BUILD_WEB_TESTS=ON and run with ctest -R web::test_routing_extensions -j1.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/network/http_server.hpp>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define IORA_TSAN 1
#endif
#endif
#if defined(__SANITIZE_THREAD__)
#define IORA_TSAN 1
#endif

using iora::network::HttpServer;
using iora::network::SessionId;
using Request = HttpServer::Request;
using Response = HttpServer::Response;

namespace
{

// Distinct port per server instance to avoid TIME_WAIT collisions (ctest -j1).
std::atomic<int> g_nextPort{18080};
int nextPort() { return g_nextPort.fetch_add(1); }

std::string lower(std::string s)
{
  for (char &c : s)
  {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return s;
}

std::string trim(const std::string &s)
{
  std::size_t a = s.find_first_not_of(" \t");
  std::size_t b = s.find_last_not_of(" \t\r\n");
  if (a == std::string::npos)
  {
    return "";
  }
  return s.substr(a, b - a + 1);
}

struct RawResponse
{
  bool ok = false;
  int status = 0;
  std::map<std::string, std::string> headers; // lowercased keys
  std::string body;
  std::string rawHead; // verbatim header block (for framing assertions)

  bool hasHeader(const std::string &k) const { return headers.count(lower(k)) > 0; }
  std::string header(const std::string &k) const
  {
    auto it = headers.find(lower(k));
    return it == headers.end() ? "" : it->second;
  }
};

// Minimal raw HTTP/1.1 client over a POSIX socket — needed because HttpClient
// cannot send HEAD/OPTIONS/PUT/PATCH/custom methods and abstracts away the wire
// bytes these tests assert on (empty-body-with-Content-Length, 204 framing,
// keep-alive reuse, suppressed non-HTTP bytes).
class RawConn
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
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    ::setsockopt(_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
    {
      ::close(_fd);
      _fd = -1;
      return false;
    }
    return true;
  }

  ~RawConn()
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

  void sendRequest(const std::string &method, const std::string &target,
                   const std::string &extraHeaders = "", const std::string &body = "",
                   bool keepAlive = false)
  {
    std::string req = method + " " + target + " HTTP/1.1\r\n";
    req += "Host: 127.0.0.1\r\n";
    req += std::string("Connection: ") + (keepAlive ? "keep-alive" : "close") + "\r\n";
    if (!body.empty())
    {
      req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    req += extraHeaders;
    req += "\r\n";
    req += body;
    sendRaw(req);
  }

  // Read whatever bytes arrive within one recv window (for non-HTTP / suppressed
  // streams). Drains the internal buffer first.
  std::string readSome()
  {
    if (!_buf.empty())
    {
      std::string out;
      out.swap(_buf);
      return out;
    }
    char tmp[4096];
    ssize_t n = ::recv(_fd, tmp, sizeof(tmp), 0);
    if (n <= 0)
    {
      return "";
    }
    return std::string(tmp, static_cast<std::size_t>(n));
  }

  // Returns true iff the peer (server) closed the connection — recv() returns 0
  // (EOF), distinct from a timeout (n<0). Drains any pending server bytes first
  // (the size-limit close paths send nothing, so EOF arrives promptly). Bounded
  // by the socket SO_RCVTIMEO so a hung server fails the assertion rather than
  // blocking the suite.
  bool peerClosed()
  {
    char tmp[4096];
    for (;;)
    {
      ssize_t n = ::recv(_fd, tmp, sizeof(tmp), 0);
      if (n == 0)
      {
        return true; // EOF — server closed the connection
      }
      if (n < 0)
      {
        return false; // timeout (server still holding the connection open)
      }
      // n > 0: server sent bytes (none expected for limit closes) — keep reading
      // until EOF or timeout.
    }
  }

  // Parse one HTTP response. Body-length rules: HEAD / 204 / 304 carry no body;
  // otherwise read Content-Length bytes (or until close if absent).
  RawResponse readResponse(const std::string &method)
  {
    RawResponse r;
    std::size_t hdrEnd = std::string::npos;
    while ((hdrEnd = _buf.find("\r\n\r\n")) == std::string::npos)
    {
      if (!fill())
      {
        break;
      }
    }
    if (hdrEnd == std::string::npos)
    {
      return r;
    }
    r.rawHead = _buf.substr(0, hdrEnd);
    _buf.erase(0, hdrEnd + 4);

    std::size_t lineEnd = r.rawHead.find("\r\n");
    std::string statusLine =
      lineEnd == std::string::npos ? r.rawHead : r.rawHead.substr(0, lineEnd);
    {
      std::istringstream ss(statusLine);
      std::string ver;
      ss >> ver >> r.status;
    }
    std::size_t pos = (lineEnd == std::string::npos) ? r.rawHead.size() : lineEnd + 2;
    while (pos < r.rawHead.size())
    {
      std::size_t e = r.rawHead.find("\r\n", pos);
      if (e == std::string::npos)
      {
        e = r.rawHead.size();
      }
      std::string line = r.rawHead.substr(pos, e - pos);
      std::size_t colon = line.find(':');
      if (colon != std::string::npos)
      {
        r.headers[lower(trim(line.substr(0, colon)))] = trim(line.substr(colon + 1));
      }
      pos = e + 2;
    }

    const bool noBody = (method == "HEAD" || r.status == 204 || r.status == 304);
    if (!noBody)
    {
      auto it = r.headers.find("content-length");
      if (it != r.headers.end())
      {
        std::size_t len = static_cast<std::size_t>(std::stoul(it->second));
        while (_buf.size() < len)
        {
          if (!fill())
          {
            break;
          }
        }
        std::size_t take = std::min(len, _buf.size());
        r.body = _buf.substr(0, take);
        _buf.erase(0, take);
      }
      else
      {
        while (fill())
        {
        }
        r.body.swap(_buf);
      }
    }
    r.ok = true;
    return r;
  }

private:
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

// One-shot request helper (Connection: close).
RawResponse rawRequest(int port, const std::string &method, const std::string &target,
                       const std::string &extraHeaders = "", const std::string &body = "")
{
  RawConn c;
  REQUIRE(c.open(port));
  c.sendRequest(method, target, extraHeaders, body, /*keepAlive=*/false);
  return c.readResponse(method);
}

// Test subclass exposing the protected SSE primitives + the suppression seam.
class TestServer : public HttpServer
{
public:
  using HttpServer::HttpServer;

  void testSendRawForSse(SessionId sid, const std::string &s)
  {
    sendRawForSse(sid, reinterpret_cast<const std::uint8_t *>(s.data()), s.size());
  }
  void testMarkUpgraded(SessionId sid) { markSessionUpgraded(sid); }
  void testCloseSession(SessionId sid) { closeSession(sid); }
  static std::string statusText(int code) { return HttpServer::getStatusText(code); }

  std::function<bool(SessionId, const Request &, Response &)> onSuppressedHook;
  bool onResponseSuppressed(SessionId sid, const Request &req, Response &res) override
  {
    return onSuppressedHook ? onSuppressedHook(sid, req, res) : false;
  }
};

// Start a server on a fresh port; returns the port. Sleeps briefly so the
// listener is ready before clients connect.
int startOn(HttpServer &srv)
{
  int port = nextPort();
  srv.setPort(port);
  srv.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  return port;
}

} // namespace

// ---------------------------------------------------------------------------
// Phase 3.1 / 3.5.1 — routing match: exact, named, wildcard, precedence,
// registration order, empty-suffix, literal colon, param-vs-query, raw capture,
// double-slash.
// ---------------------------------------------------------------------------

TEST_CASE("routing: exact match + backward compat + literal colon (R-9)", "[routing][match]")
{
  TestServer srv;
  srv.onGet("/users", [](const Request &, Response &res) { res.set_content("USERS", "text/plain"); });
  srv.onGet("/time/12:30",
            [](const Request &, Response &res) { res.set_content("T", "text/plain"); });
  srv.onGet("/a:b", [](const Request &, Response &res) { res.set_content("AB", "text/plain"); });
  int port = startOn(srv);

  REQUIRE(rawRequest(port, "GET", "/users").body == "USERS");
  // Trailing slash and extra segment must NOT match the exact route.
  REQUIRE(rawRequest(port, "GET", "/users/").status == 404);
  REQUIRE(rawRequest(port, "GET", "/users/1").status == 404);
  // Literal colon (R-9): ':' not at segment start is literal.
  REQUIRE(rawRequest(port, "GET", "/time/12:30").body == "T");
  REQUIRE(rawRequest(port, "GET", "/a:b").body == "AB");

  srv.stop();
}

TEST_CASE("routing: named segments + multiple + param-vs-query + raw capture", "[routing][named]")
{
  TestServer srv;
  srv.onGet("/users/:id",
            [](const Request &req, Response &res) { res.set_content(req.params.at("id"), "text/plain"); });
  srv.onGet("/a/:x/b/:y", [](const Request &req, Response &res)
            { res.set_content(req.params.at("x") + "," + req.params.at("y"), "text/plain"); });
  int port = startOn(srv);

  REQUIRE(rawRequest(port, "GET", "/users/42").body == "42");
  // Too few / too many segments do not match a single named segment.
  REQUIRE(rawRequest(port, "GET", "/users").status == 404);
  REQUIRE(rawRequest(port, "GET", "/users/42/x").status == 404);
  // Multiple named segments capture both; literal between must match.
  REQUIRE(rawRequest(port, "GET", "/a/7/b/9").body == "7,9");
  REQUIRE(rawRequest(port, "GET", "/a/7/c/9").status == 404);
  // Path param wins over a same-named query param (applied after query parse).
  REQUIRE(rawRequest(port, "GET", "/users/7?id=9").body == "7");
  // Captures are stored RAW (not percent-decoded).
  REQUIRE(rawRequest(port, "GET", "/users/a%2Fb").body == "a%2Fb");

  srv.stop();
}

TEST_CASE("routing: trailing wildcard + empty-suffix (M-R1) + double-slash + query", "[routing][wildcard]")
{
  TestServer srv;
  srv.onGet("/static/*",
            [](const Request &req, Response &res) { res.set_content("[" + req.pathRest + "]", "text/plain"); });
  int port = startOn(srv);

  REQUIRE(rawRequest(port, "GET", "/static/css/app.css").body == "[css/app.css]");
  // Empty-suffix: both "/static" and "/static/" match with pathRest == "".
  REQUIRE(rawRequest(port, "GET", "/static").body == "[]");
  REQUIRE(rawRequest(port, "GET", "/static/").body == "[]");
  // Interior double-slash preserved: pathRest == "/x" (SR-19, single pinned value).
  REQUIRE(rawRequest(port, "GET", "/static//x").body == "[/x]");
  // Query string is stripped before suffix capture (SR-LOW).
  REQUIRE(rawRequest(port, "GET", "/static/app.js?v=2").body == "[app.js]");
  // Auto-HEAD works through the wildcard matcher: HEAD on a wildcard GET route
  // runs the GET handler, then strips the body while preserving Content-Length.
  auto head = rawRequest(port, "HEAD", "/static/x");
  REQUIRE(head.status == 200);
  REQUIRE(head.body.empty());
  REQUIRE(head.header("Content-Length") == "3"); // "[x]" length, body dropped

  srv.stop();
}

TEST_CASE("routing: precedence (exact>named>wildcard) + registration order", "[routing][precedence]")
{
  TestServer srv;
  // exact > named: register named first, exact second.
  srv.onGet("/users/:id", [](const Request &, Response &res) { res.set_content("NAMED", "text/plain"); });
  srv.onGet("/users/me", [](const Request &, Response &res) { res.set_content("EXACT", "text/plain"); });
  // named > wildcard: register wildcard first, named second.
  srv.onGet("/files/*", [](const Request &, Response &res) { res.set_content("WILD", "text/plain"); });
  srv.onGet("/files/:name", [](const Request &, Response &res) { res.set_content("FNAMED", "text/plain"); });
  // within-precedence registration order: two overlapping wildcards, first wins.
  srv.onGet("/w/*", [](const Request &, Response &res) { res.set_content("W1", "text/plain"); });
  srv.onGet("/w/*", [](const Request &, Response &res) { res.set_content("W2", "text/plain"); });
  int port = startOn(srv);

  REQUIRE(rawRequest(port, "GET", "/users/me").body == "EXACT");
  REQUIRE(rawRequest(port, "GET", "/users/123").body == "NAMED");
  REQUIRE(rawRequest(port, "GET", "/files/x").body == "FNAMED");
  REQUIRE(rawRequest(port, "GET", "/w/anything").body == "W1");

  srv.stop();
}

TEST_CASE("routing: malformed patterns throw std::invalid_argument at registration", "[routing][parse]")
{
  TestServer srv;
  auto noop = [](const Request &, Response &) {};
  REQUIRE_THROWS_AS(srv.onGet("/users/:", noop), std::invalid_argument);    // empty name
  REQUIRE_THROWS_AS(srv.onGet("/a/*/b", noop), std::invalid_argument);      // non-terminal wildcard
  REQUIRE_THROWS_AS(srv.onGet("/a/:1bad", noop), std::invalid_argument);    // name not [A-Za-z_]...
  REQUIRE_THROWS_AS(srv.onGet("/a/foo*bar", noop), std::invalid_argument);  // '*' mixed in segment
  // Valid patterns do not throw.
  REQUIRE_NOTHROW(srv.onGet("/ok/:id", noop));
  REQUIRE_NOTHROW(srv.onGet("/ok2/*", noop));
}

// ---------------------------------------------------------------------------
// Phase 3.2 / 3.5.2 — setDefaultHandler + OPTIONS/HEAD no-route fallthrough.
// ---------------------------------------------------------------------------

TEST_CASE("routing: setDefaultHandler custom + 404 fallback + OPTIONS/HEAD fallthrough", "[routing][default]")
{
  SECTION("no default handler -> hard-coded 404")
  {
    TestServer srv;
    srv.onGet("/known", [](const Request &, Response &res) { res.set_content("K", "text/plain"); });
    int port = startOn(srv);
    REQUIRE(rawRequest(port, "GET", "/missing").status == 404);
    srv.stop();
  }

  SECTION("custom default handler invoked; OPTIONS/HEAD on no-route fall through to it (SR-3)")
  {
    TestServer srv;
    srv.onGet("/known", [](const Request &, Response &res) { res.set_content("K", "text/plain"); });
    srv.setDefaultHandler([](const Request &, Response &res)
                          { res.status = 404; res.set_content("CUSTOM-404", "text/plain"); });
    int port = startOn(srv);

    auto r = rawRequest(port, "GET", "/missing");
    REQUIRE(r.status == 404);
    REQUIRE(r.body == "CUSTOM-404");
    // OPTIONS on a no-route path falls through to the default handler.
    REQUIRE(rawRequest(port, "OPTIONS", "/missing").status == 404);
    // HEAD on a path with no GET falls through to the default handler (bodyless).
    REQUIRE(rawRequest(port, "HEAD", "/missing").status == 404);

    srv.stop();
  }
}

// ---------------------------------------------------------------------------
// Phase 3.3 / 3.5.3 — 405 + Allow correctness, framing, safety net.
// ---------------------------------------------------------------------------

TEST_CASE("routing: 405 + Allow correctness + framing (SR-2/SR-5)", "[routing][405]")
{
  TestServer srv;
  srv.onGet("/users/:id", [](const Request &, Response &res) { res.set_content("G", "text/plain"); });
  srv.onPost("/users/:id", [](const Request &, Response &res) { res.set_content("P", "text/plain"); });
  srv.onGet("/static/*", [](const Request &, Response &res) { res.set_content("S", "text/plain"); });
  int port = startOn(srv);

  REQUIRE(rawRequest(port, "GET", "/users/5").status == 200);

  // 405 Allow lists the full synthesized set (HEAD from GET, OPTIONS self), in
  // canonical order — identical to the OPTIONS Allow for the same resource.
  auto del = rawRequest(port, "DELETE", "/users/5");
  REQUIRE(del.status == 405);
  REQUIRE(del.header("Allow") == "GET, HEAD, POST, OPTIONS");
  REQUIRE(del.hasHeader("Content-Length")); // framing preserved (set_content)
  REQUIRE(del.header("Content-Type") == "text/plain");

  // 405 under a wildcard route -> Allow contains GET (non-empty, unlike old).
  auto wild = rawRequest(port, "POST", "/static/x");
  REQUIRE(wild.status == 405);
  REQUIRE(wild.header("Allow") == "GET, HEAD, OPTIONS");

  srv.stop();
}

TEST_CASE("routing: safety net catch(std::exception) / catch(...) / default-handler guard", "[routing][safetynet]")
{
  TestServer srv;
  srv.onGet("/boom", [](const Request &, Response &)
            { throw std::runtime_error("boom"); });
  srv.onGet("/boom2", [](const Request &, Response &) { throw 42; });
  srv.onGet("/ok", [](const Request &, Response &res) { res.set_content("OK", "text/plain"); });
  srv.setDefaultHandler([](const Request &, Response &) { throw std::runtime_error("default-boom"); });
  int port = startOn(srv);

  REQUIRE(rawRequest(port, "GET", "/boom").status == 500);
  REQUIRE(rawRequest(port, "GET", "/boom2").status == 500);    // catch(...)
  REQUIRE(rawRequest(port, "GET", "/no-route").status == 500); // throwing default handler
  // Worker survives: subsequent requests still served.
  REQUIRE(rawRequest(port, "GET", "/ok").body == "OK");

  srv.stop();
}

// ---------------------------------------------------------------------------
// Phase 3.3 / 3.5.5 — auto-HEAD, auto-OPTIONS, OPTIONS *, keep-alive framing,
// getStatusText.
// ---------------------------------------------------------------------------

TEST_CASE("routing: auto HEAD-for-GET preserves Content-Length with empty body (RD-21/SR-5)", "[routing][head]")
{
  TestServer srv;
  srv.onGet("/page", [](const Request &, Response &res)
            { res.set_content("HELLO-BODY", "text/plain"); }); // 10-byte body
  int port = startOn(srv);

  auto head = rawRequest(port, "HEAD", "/page");
  REQUIRE(head.status == 200);
  REQUIRE(head.header("Content-Length") == "10"); // reflects the GET body length
  REQUIRE(head.header("Content-Type") == "text/plain");
  REQUIRE(head.body.empty()); // headers-only on the wire

  srv.stop();
}

TEST_CASE("routing: keep-alive framing after HEAD (SR-5)", "[routing][head][keepalive]")
{
  TestServer srv;
  srv.onGet("/page", [](const Request &, Response &res) { res.set_content("HELLO-BODY", "text/plain"); });
  int port = startOn(srv);

  RawConn c;
  REQUIRE(c.open(port));
  c.sendRequest("HEAD", "/page", "", "", /*keepAlive=*/true);
  auto h = c.readResponse("HEAD");
  REQUIRE(h.status == 200);
  REQUIRE(h.header("Content-Length") == "10");
  REQUIRE(h.body.empty());
  // A second request on the SAME connection must be received intact (no phantom
  // body bytes from the HEAD desynced the stream).
  c.sendRequest("GET", "/page", "", "", /*keepAlive=*/false);
  auto g = c.readResponse("GET");
  REQUIRE(g.status == 200);
  REQUIRE(g.body == "HELLO-BODY");

  srv.stop();
}

TEST_CASE("routing: auto OPTIONS -> 204 + Allow; OPTIONS * -> 200 CL:0 no Allow (SR-1/SR-21)", "[routing][options]")
{
  TestServer srv;
  srv.onGet("/users/:id", [](const Request &, Response &res) { res.set_content("G", "text/plain"); });
  srv.onPost("/users/:id", [](const Request &, Response &res) { res.set_content("P", "text/plain"); });
  int port = startOn(srv);

  auto opt = rawRequest(port, "OPTIONS", "/users/5");
  REQUIRE(opt.status == 204);
  REQUIRE(opt.header("Allow") == "GET, HEAD, POST, OPTIONS");
  REQUIRE_FALSE(opt.hasHeader("Content-Length")); // 204 omits Content-Length
  REQUIRE_FALSE(opt.hasHeader("Content-Type"));   // and no inherited Content-Type

  // OPTIONS on a no-route path with no default handler -> 404.
  REQUIRE(rawRequest(port, "OPTIONS", "/no-route").status == 404);

  // Asterisk-form OPTIONS * -> 200 + Content-Length: 0 + no Allow + no Content-Type.
  auto star = rawRequest(port, "OPTIONS", "*");
  REQUIRE(star.status == 200);
  REQUIRE(star.header("Content-Length") == "0");
  REQUIRE_FALSE(star.hasHeader("Allow"));
  REQUIRE_FALSE(star.hasHeader("Content-Type"));

  srv.stop();
}

TEST_CASE("routing: getStatusText 304/426", "[routing][status]")
{
  REQUIRE(TestServer::statusText(304) == "Not Modified");
  REQUIRE(TestServer::statusText(426) == "Upgrade Required");
}

TEST_CASE("routing: HEAD x 304 -> bodyless, no contradictory Content-Length (SR-18)", "[routing][head][304]")
{
  TestServer srv;
  // A conditional GET handler that returns a proper 304 (no body, no body-length
  // header — it manages its own response headers, as a real asset handler does).
  srv.onGet("/asset", [](const Request &, Response &res)
            {
              res.status = 304;
              res.body.clear();
              res.headers.erase("Content-Length");
              res.headers.erase("Content-Type");
            });
  int port = startOn(srv);

  auto head = rawRequest(port, "HEAD", "/asset");
  REQUIRE(head.status == 304);
  REQUIRE(head.body.empty());
  // auto-HEAD must NOT synthesize/keep a contradictory body Content-Length for a
  // bodyless status (SR-18): the dispatcher leaves the handler's 304 untouched.
  if (head.hasHeader("Content-Length"))
  {
    REQUIRE(head.header("Content-Length") == "0");
  }

  srv.stop();
}

TEST_CASE("routing: method tokens are case-sensitive; unknown -> 501, malformed -> 400 (RFC 9110)",
          "[routing][method]")
{
  TestServer srv;
  srv.onGet("/x", [](const Request &, Response &res) { res.set_content("X", "text/plain"); });
  int port = startOn(srv);

  // Canonical uppercase GET dispatches (the only conformant spelling).
  REQUIRE(rawRequest(port, "GET", "/x").body == "X");
  // RFC 9110 §9.1: method names are CASE-SENSITIVE. Lowercase 'get'/'head' and
  // MIXED-case 'Get' are well-formed tokens but NOT the registered methods ->
  // 501 Not Implemented. ('Get' is the key regression pin: the old code
  // upper-cased and dispatched it as GET.)
  REQUIRE(rawRequest(port, "get", "/x").status == 501);
  REQUIRE(rawRequest(port, "head", "/x").status == 501);
  REQUIRE(rawRequest(port, "Get", "/x").status == 501);
  REQUIRE(rawRequest(port, "Post", "/x").status == 501);
  // A well-formed but unsupported method -> 501 Not Implemented (RFC 9110 §15.6.2).
  REQUIRE(rawRequest(port, "FOOBAR", "/x").status == 501);
  REQUIRE(rawRequest(port, "PROPFIND", "/x").status == 501);
  // A malformed method token (illegal non-tchar char per RFC 9110 §5.6.2) -> 400.
  REQUIRE(rawRequest(port, "G@T", "/x").status == 400);
  REQUIRE(rawRequest(port, "BAD(METHOD)", "/x").status == 400);

  // Request-line robustness (same parser), each over a fresh connection:
  auto rawStatus = [&](const std::string &requestLineAndRest) -> int
  {
    RawConn vc;
    REQUIRE(vc.open(port));
    vc.sendRaw(requestLineAndRest);
    return vc.readResponse("GET").status;
  };
  // Malformed HTTP-version (syntax error) -> 400 (web-M3, RFC 9110 §15.5.1).
  REQUIRE(rawStatus("GET /x HTTP/x.y\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 400);
  // Missing HTTP-version -> 400.
  REQUIRE(rawStatus("GET /x\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 400);
  // Extra token on the request line -> 400 (RFC 9112 §3, exactly 3 fields).
  REQUIRE(rawStatus("GET /x HTTP/1.1 junk\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 400);
  // Well-formed but UNSUPPORTED major version -> 505 (RFC 9110 §15.5.6).
  REQUIRE(rawStatus("GET /x HTTP/2.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 505);
  REQUIRE(rawStatus("GET /x HTTP/0.9\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 505);
  REQUIRE(rawStatus("GET /x HTTP/3.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 505);
  // HTTP/1.0 (major 1, older minor) is still accepted and dispatches normally.
  REQUIRE(rawStatus("GET /x HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 200);
  // RFC 9112 §2.3: HTTP-version is EXACTLY one DIGIT per component. Multi-digit,
  // leading-zero, sign, or trailing-junk versions are MALFORMED (400), NOT 505 —
  // std::stoi would have accepted/misrouted these.
  REQUIRE(rawStatus("GET /x HTTP/11.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 400);
  REQUIRE(rawStatus("GET /x HTTP/01.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 400);
  REQUIRE(rawStatus("GET /x HTTP/1.1xyz\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 400);
  REQUIRE(rawStatus("GET /x HTTP/+1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") == 400);

  srv.stop();
}

TEST_CASE("http_message: parseMethod case-sensitive + RFC 9110 token validation (unit)",
          "[parser][method]")
{
  using iora::network::HttpMethod;
  using iora::network::HttpRequestError;
  using iora::network::parseMethod;

  REQUIRE(parseMethod("GET") == HttpMethod::GET);
  REQUIRE(parseMethod("TRACE") == HttpMethod::TRACE);

  auto expectStatus = [](const std::string &m, int status)
  {
    bool threw = false;
    try
    {
      parseMethod(m);
    }
    catch (const HttpRequestError &e)
    {
      threw = true;
      REQUIRE(e.status() == status);
    }
    REQUIRE(threw);
  };

  expectStatus("Get", 501);    // mixed-case recognized name -> unsupported
  expectStatus("get", 501);    // lowercase recognized name -> unsupported
  expectStatus("FOOBAR", 501); // well-formed unknown -> unsupported
  expectStatus("", 400);       // empty -> not a token (isHttpToken("") false)
  expectStatus("G@T", 400);    // delimiter '@' -> malformed token
  expectStatus(std::string("G\xC0T"), 400); // high byte 0xC0 -> not an ASCII tchar (web-M1 pin)
}

// ---------------------------------------------------------------------------
// Phase 3.4 / 3.5.4 + 3.5.5 — SSE suppression primitives, sid population,
// no-self-deadlock, suppression cleared on throw.
// ---------------------------------------------------------------------------

TEST_CASE("routing: Request::sid default sentinel is 0 (RD-22)", "[routing][sid]")
{
  Request r;
  REQUIRE(r.sid == 0u);
  Response res;
  REQUIRE_FALSE(res._suppressSend);
}

TEST_CASE("routing: SSE suppression all-or-nothing + sendRawForSse + sid + no-self-deadlock", "[routing][sse]")
{
  TestServer srv;
  // A GET handler writes a preamble (embedding its sid) DIRECTLY via
  // sendRawForSse on its own session, marks the session upgraded, and suppresses
  // the terminal response. Proves: suppression (no HTTP response), sendRawForSse
  // delivery to req.sid, correct (non-zero) sid, and no self-deadlock (handler
  // completed under the narrowed lock).
  srv.onGet("/sse", [&srv](const Request &req, Response &res)
            {
              std::string preamble = "SSE-PREAMBLE-" + std::to_string(req.sid);
              srv.testMarkUpgraded(req.sid);
              srv.testSendRawForSse(req.sid, preamble);
              res._suppressSend = true;
            });
  int port = startOn(srv);

  RawConn c;
  REQUIRE(c.open(port));
  c.sendRequest("GET", "/sse", "", "", /*keepAlive=*/true);
  std::string got;
  // Collect what arrives (the preamble bytes), not an HTTP response.
  for (int i = 0; i < 5 && got.find("SSE-PREAMBLE-") == std::string::npos; ++i)
  {
    got += c.readSome();
  }
  REQUIRE(got.find("SSE-PREAMBLE-") != std::string::npos);
  REQUIRE(got.find("HTTP/1.1") == std::string::npos); // NO terminal HTTP response
  // sid embedded in the preamble is a real (non-zero) session id.
  std::size_t p = got.find("SSE-PREAMBLE-") + std::string("SSE-PREAMBLE-").size();
  REQUIRE(std::stoull(got.substr(p)) != 0u);

  srv.stop();
}

TEST_CASE("routing: subclass onResponseSuppressed seam suppresses the terminal response", "[routing][sse][seam]")
{
  TestServer srv;
  srv.onGet("/seam", [&srv](const Request &req, Response &)
            { srv.testSendRawForSse(req.sid, "SEAM-BYTES"); srv.testMarkUpgraded(req.sid); });
  srv.onSuppressedHook = [](SessionId, const Request &req, Response &)
  { return req.path == "/seam"; };
  int port = startOn(srv);

  RawConn c;
  REQUIRE(c.open(port));
  c.sendRequest("GET", "/seam", "", "", /*keepAlive=*/true);
  std::string got;
  for (int i = 0; i < 5 && got.find("SEAM-BYTES") == std::string::npos; ++i)
  {
    got += c.readSome();
  }
  REQUIRE(got.find("SEAM-BYTES") != std::string::npos);
  REQUIRE(got.find("HTTP/1.1") == std::string::npos);

  srv.stop();
}

TEST_CASE("routing: suppression cleared on throw -> terminal 500 still sent (RD-9)", "[routing][sse][throw]")
{
  TestServer srv;
  srv.onGet("/throwsupp", [](const Request &, Response &res)
            { res._suppressSend = true; throw std::runtime_error("after-suppress"); });
  int port = startOn(srv);

  auto r = rawRequest(port, "GET", "/throwsupp");
  REQUIRE(r.status == 500); // safety net cleared suppression, sent 500

  srv.stop();
}

TEST_CASE("routing: handler closeSession/sendRawForSse on its own session does not deadlock", "[routing][sse][close]")
{
  TestServer srv;
  std::atomic<bool> handlerDone{false};
  srv.onGet("/closeself", [&srv, &handlerDone](const Request &req, Response &res)
            {
              srv.testSendRawForSse(req.sid, "X"); // takes _mutex from inside a handler
              srv.testCloseSession(req.sid);       // takes _mutex from inside a handler
              res._suppressSend = true;
              handlerDone.store(true); // set ONLY after both _mutex-taking calls return
            });
  int port = startOn(srv);

  RawConn c;
  REQUIRE(c.open(port));
  c.sendRequest("GET", "/closeself");

  // Hard watchdog: if the handler deadlocked under the old held-mutex, the flag
  // never sets and this bounded wait fails the test (rather than hanging CI).
  bool done = false;
  for (int i = 0; i < 200 && !done; ++i)
  {
    done = handlerDone.load();
    if (!done)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }
  REQUIRE(done); // handler completed (no self-deadlock) within ~2s

  srv.stop();
}

// ---------------------------------------------------------------------------
// handleIncomingData size-limit / parse-error close paths (tracker 2026-05-30-2):
// each must close the connection through the GUARDED closeSession (was an
// unguarded raw _transport->close — UAF risk vs stop(); the buffer-limit site
// also ran under _sessionMutex, so the fix defers the close to outside that lock
// to avoid a _sessionMutex->_mutex inversion). The server must CLEANLY close the
// socket (EOF), not hang.
// ---------------------------------------------------------------------------

TEST_CASE("routing: invalid Content-Length closes the connection", "[routing][limits]")
{
  TestServer srv;
  srv.onPost("/x", [](const Request &, Response &res) { res.set_content("ok", "text/plain"); });
  int port = startOn(srv);

  RawConn c;
  REQUIRE(c.open(port));
  c.sendRaw("POST /x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: notanumber\r\n\r\n");
  REQUIRE(c.peerClosed()); // closeSession ran (loop site, no lock held)

  srv.stop();
}

TEST_CASE("routing: Content-Length over MAX_BODY_SIZE closes the connection", "[routing][limits]")
{
  TestServer srv;
  srv.onPost("/x", [](const Request &, Response &res) { res.set_content("ok", "text/plain"); });
  int port = startOn(srv);

  RawConn c;
  REQUIRE(c.open(port));
  // 20 MB declared (> MAX_BODY_SIZE 10 MB); the header alone triggers the close
  // before any body is sent.
  c.sendRaw("POST /x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 20000000\r\n\r\n");
  REQUIRE(c.peerClosed());

  srv.stop();
}

TEST_CASE("routing: header block over MAX_HEADER_SIZE closes the connection", "[routing][limits]")
{
  TestServer srv;
  srv.onGet("/x", [](const Request &, Response &res) { res.set_content("ok", "text/plain"); });
  int port = startOn(srv);

  RawConn c;
  REQUIRE(c.open(port));
  // > 64 KB of header bytes before the terminator (loop site, no lock held).
  std::string req = "GET /x HTTP/1.1\r\nHost: 127.0.0.1\r\n";
  req += "X-Big: ";
  req += std::string(70 * 1024, 'a');
  req += "\r\n\r\n";
  c.sendRaw(req);
  REQUIRE(c.peerClosed());

  srv.stop();
}

TEST_CASE("routing: per-session buffer over MAX_BUFFER_SIZE closes without deadlock",
          "[routing][limits]")
{
  TestServer srv;
  srv.onGet("/x", [](const Request &, Response &res) { res.set_content("ok", "text/plain"); });
  int port = startOn(srv);

  RawConn c;
  REQUIRE(c.open(port));
  // > 1 MB with NO "\r\n\r\n" terminator, so it accumulates in the per-session
  // buffer and trips MAX_BUFFER_SIZE — the site that runs under _sessionMutex.
  // The capture-then-close fix must close the socket cleanly (no inversion/hang).
  c.sendRaw("GET /x HTTP/1.1\r\n");
  c.sendRaw(std::string(1024 * 1024 + 4096, 'Z'));
  REQUIRE(c.peerClosed()); // closed via the deferred guarded closeSession

  srv.stop();
}

// ---------------------------------------------------------------------------
// Phase 3.5.4 — concurrency (no serialization) + 3.5.4(g) stop() no-2s-stall.
// ---------------------------------------------------------------------------

TEST_CASE("routing: handlers no longer fully serialize (_mutex narrowing)", "[routing][concurrency]")
{
  TestServer srv;
  srv.onGet("/slow", [](const Request &, Response &res)
            { std::this_thread::sleep_for(std::chrono::milliseconds(200));
              res.set_content("S", "text/plain"); });
  int port = startOn(srv);

  const int N = 4;
  auto t0 = std::chrono::steady_clock::now();
  std::vector<std::thread> threads;
  std::atomic<int> oks{0};
  for (int i = 0; i < N; ++i)
  {
    threads.emplace_back([&]
                         { if (rawRequest(port, "GET", "/slow").body == "S") oks.fetch_add(1); });
  }
  for (auto &t : threads)
  {
    t.join();
  }
  auto elapsedMs =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
      .count();

  REQUIRE(oks.load() == N);
#ifndef IORA_TSAN
  // If serialized, total would be >= N*200ms = 800ms. Concurrency keeps it well
  // under that. (Skipped under TSAN, which perturbs timing — SR-16.)
  REQUIRE(elapsedMs < 600);
#endif

  srv.stop();
}

TEST_CASE("routing: stop() with an in-flight handler completes well under the 2s timeout (SR-22)", "[routing][shutdown]")
{
  auto srv = std::make_unique<TestServer>();
  srv->onGet("/slow", [](const Request &, Response &res)
             { std::this_thread::sleep_for(std::chrono::milliseconds(400));
               res.set_content("S", "text/plain"); });
  int port = startOn(*srv);

  std::thread req([&] { rawRequest(port, "GET", "/slow"); });
  std::this_thread::sleep_for(std::chrono::milliseconds(100)); // ensure in-flight

  auto t0 = std::chrono::steady_clock::now();
  srv->stop();
  auto stopMs =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
      .count();
  req.join();

  // The drain waits for the ~400ms handler, then resets — NOT the 2s force-
  // shutdown timeout. A deadlock would manifest as ~2s+.
  REQUIRE(stopMs < 1800);
}

TEST_CASE("routing: HEAD is bodyless on every terminal path + auto-HEAD ignores suppression (SR-4/§9.3.2)", "[routing][head][framing]")
{
  TestServer srv;
  srv.onPost("/postonly", [](const Request &, Response &res) { res.set_content("P", "text/plain"); });
  // A non-SSE GET handler that erroneously suppresses: under HEAD it must NOT
  // become a half-open socket (SR-4 forces a normal bodyless HEAD response).
  srv.onGet("/suppressing", [](const Request &, Response &res)
            { res._suppressSend = true; res.set_content("BODY", "text/plain"); });
  int port = startOn(srv);

  // HEAD on a no-route path -> 404 with EMPTY wire body; keep-alive intact.
  {
    RawConn c;
    REQUIRE(c.open(port));
    c.sendRequest("HEAD", "/missing", "", "", /*keepAlive=*/true);
    auto h = c.readResponse("HEAD");
    REQUIRE(h.status == 404);
    REQUIRE(h.body.empty());
    c.sendRequest("POST", "/postonly", "", "x", /*keepAlive=*/false);
    auto p = c.readResponse("POST");
    REQUIRE(p.status == 200);
    REQUIRE(p.body == "P"); // second request on the same connection is intact
  }

  // HEAD on a POST-only path -> 405 with EMPTY wire body + Allow.
  {
    auto h = rawRequest(port, "HEAD", "/postonly");
    REQUIRE(h.status == 405);
    REQUIRE(h.body.empty());
    REQUIRE(h.header("Allow") == "POST, OPTIONS");
  }

  // SR-4: HEAD into the suppressing GET handler -> normal bodyless 200, NOT a
  // half-open socket; keep-alive stays usable.
  {
    RawConn c;
    REQUIRE(c.open(port));
    c.sendRequest("HEAD", "/suppressing", "", "", /*keepAlive=*/true);
    auto h = c.readResponse("HEAD");
    REQUIRE(h.status == 200);
    REQUIRE(h.body.empty());
    c.sendRequest("GET", "/postonly", "", "", /*keepAlive=*/false);
    auto g = c.readResponse("GET");
    REQUIRE(g.status == 405); // GET not allowed on /postonly; connection still alive
  }

  srv.stop();
}

TEST_CASE("routing: HEAD x 304 with a stale Content-Length is reconciled by the dispatcher (SR-18)", "[routing][head][304]")
{
  TestServer srv;
  // A GET handler that set_content's a representation (Content-Length: 14) then
  // downgrades to 304 — leaving a stale body Content-Length.
  srv.onGet("/cond", [](const Request &, Response &res)
            { res.set_content("REPRESENTATION", "text/plain"); res.status = 304; });
  int port = startOn(srv);

  auto h = rawRequest(port, "HEAD", "/cond");
  REQUIRE(h.status == 304);
  REQUIRE(h.body.empty());
  // The dispatcher drops the contradictory body Content-Length for a bodyless
  // 304 on the HEAD path (SR-18), rather than advertising 14 bytes with no body.
  REQUIRE_FALSE(h.hasHeader("Content-Length"));

  srv.stop();
}

TEST_CASE("routing: handler observes non-zero req.sid; Connection: close completes and closes (RD-22)", "[routing][sid][close]")
{
  TestServer srv;
  std::atomic<unsigned long long> seenSid{0};
  srv.onGet("/sid", [&seenSid](const Request &req, Response &res)
            { seenSid.store(static_cast<unsigned long long>(req.sid)); res.set_content("OK", "text/plain"); });
  int port = startOn(srv);

  RawConn c;
  REQUIRE(c.open(port));
  c.sendRequest("GET", "/sid", "", "", /*keepAlive=*/false); // Connection: close
  auto r = c.readResponse("GET");
  REQUIRE(r.status == 200);
  REQUIRE(r.body == "OK");
  REQUIRE(seenSid.load() != 0u); // req.sid populated at construction (RD-22/SR-15)
  // Connection: close -> the server closes after responding (no deadlock in the
  // send-block close path, SR-7); a subsequent read returns no bytes.
  REQUIRE(c.readSome().empty());

  srv.stop();
}

TEST_CASE("routing: concurrent registration vs dispatch (SR-9 — _handlers data race / realloc)", "[routing][concurrency][tsan]")
{
  TestServer srv;
  srv.onGet("/seed", [](const Request &, Response &res) { res.set_content("S", "text/plain"); });
  int port = startOn(srv);

  std::atomic<bool> stopWriter{false};
  // Writer thread: continuously register new GET routes (growing the per-method
  // vector, forcing reallocation) and swap the default handler — all table
  // writes under _mutex — concurrently with the dispatching readers below.
  std::thread writer(
    [&]
    {
      int i = 0;
      while (!stopWriter.load() && i < 5000)
      {
        srv.onGet("/r" + std::to_string(i),
                  [](const Request &, Response &res) { res.set_content("R", "text/plain"); });
        srv.setDefaultHandler([](const Request &, Response &res)
                              { res.status = 404; res.set_content("D", "text/plain"); });
        ++i;
      }
    });

  std::vector<std::thread> readers;
  std::atomic<int> seedOk{0};
  const int perReader = 40;
  for (int t = 0; t < 4; ++t)
  {
    readers.emplace_back(
      [&]
      {
        for (int k = 0; k < perReader; ++k)
        {
          // Matching /seed copies its handler BY VALUE out of the GET vector
          // under the lock while the writer reallocates that vector.
          if (rawRequest(port, "GET", "/seed").status == 200)
          {
            seedOk.fetch_add(1);
          }
          // NO_ROUTE -> the (concurrently-swapped) default handler, copied under
          // the lock.
          rawRequest(port, "GET", "/does-not-exist");
        }
      });
  }
  for (auto &t : readers)
  {
    t.join();
  }
  stopWriter.store(true);
  writer.join();

  REQUIRE(seedOk.load() == 4 * perReader); // every /seed dispatch succeeded

  srv.stop();
}

TEST_CASE("routing: stop() force-timeout reset does not crash a still-running worker (SR-22)", "[routing][shutdown][slow]")
{
  auto srv = std::make_unique<TestServer>();
  // A handler that ignores shutdown and runs LONGER than the 2s force-shutdown
  // timeout, so stop() resets _transport while this worker is still active.
  srv->onGet("/verylong", [](const Request &, Response &res)
             { std::this_thread::sleep_for(std::chrono::milliseconds(2500));
               res.set_content("S", "text/plain"); });
  int port = startOn(*srv);

  std::thread req([&] { rawRequest(port, "GET", "/verylong"); });
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  auto t0 = std::chrono::steady_clock::now();
  srv->stop(); // hits the 2s force-shutdown timeout, then resets _transport
  auto stopMs =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
      .count();
  req.join(); // the worker finishes its sleep AFTER the reset; its guarded send
              // sees _transport == nullptr and skips — no use-after-free / crash.

  // stop() returned at ~2s (force timeout), not hung; and the process survived
  // the reset-vs-straggler race (ASAN-clean).
  REQUIRE(stopMs >= 1800);
  REQUIRE(stopMs < 3500);
}
