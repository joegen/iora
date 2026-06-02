// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit/integration tests for the iora HTMX helpers (web/htmx.hpp): the five
// HX-* request inspectors (isHtmx, trigger, triggerName, target, isBoost) and
// the six response setters (setRedirect, setRefresh, setPushUrl, setRetarget,
// setReswap, setTrigger), including CR/LF rejection (M-8), dangerous-URL-scheme
// rejection (M-B), the case-insensitive header lookup (M-R4), and the
// throw->500 routing-safety-net propagation (L-3).
//
// Tracker: tasks/iora/ongoing/2026-05-29-8_htmx-support_phase7_htmx-helpers_P3.json
// Architecture (source of truth): architecture/iora/htmx_helpers.json
//
// Registered via the WEB_TESTS set in tests/CMakeLists.txt; build with
// -DIORA_BUILD_WEB_TESTS=ON and run with ctest -R web::test_htmx_helpers -j1.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/network/http_server.hpp>
#include <iora/web/htmx.hpp>

#include <arpa/inet.h>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <netinet/in.h>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <utility>

using iora::network::HttpServer;
using Request = HttpServer::Request;
using Response = HttpServer::Response;

namespace htmx = iora::web::htmx;

namespace
{

// ---------------------------------------------------------------------------
// Unit-level fixtures over the existing Request/Response structs.
// ---------------------------------------------------------------------------

Request makeReq(std::initializer_list<std::pair<std::string, std::string>> headers)
{
  Request r;
  for (const auto &h : headers)
  {
    r.headers[h.first] = h.second;
  }
  return r;
}

// Exact-key presence (the headers map is case-insensitive, so this distinguishes
// "HX-Push-Url" from "HX-PushUrl" — they differ by a hyphen, genuinely different
// keys — but treats "HX-Push-Url"/"HX-Push-URL" as equal, which is correct since
// HTTP header names are case-insensitive on the wire).
bool hasHeader(const Response &res, const std::string &k) { return res.headers.count(k) > 0; }

std::string headerValue(const Response &res, const std::string &k)
{
  auto it = res.headers.find(k);
  return it == res.headers.end() ? std::string() : it->second;
}

// ---------------------------------------------------------------------------
// Minimal raw HTTP/1.1 client (for the live wire-parsed L-e and L-3 tests),
// adapted from tests/web/test_routing_extensions.cpp.
// ---------------------------------------------------------------------------

std::atomic<int> g_nextPort{18230};
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

  bool hasHeader(const std::string &k) const { return headers.count(lower(k)) > 0; }
  std::string header(const std::string &k) const
  {
    auto it = headers.find(lower(k));
    return it == headers.end() ? "" : it->second;
  }
};

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
                   const std::string &extraHeaders, const std::string &body)
  {
    std::string req = method + " " + target + " HTTP/1.1\r\n";
    req += "Host: 127.0.0.1\r\n";
    req += "Connection: close\r\n";
    if (!body.empty())
    {
      req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    }
    req += extraHeaders;
    req += "\r\n";
    req += body;
    sendRaw(req);
  }

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
    std::string head = _buf.substr(0, hdrEnd);
    _buf.erase(0, hdrEnd + 4);

    std::size_t lineEnd = head.find("\r\n");
    std::string statusLine = lineEnd == std::string::npos ? head : head.substr(0, lineEnd);
    {
      std::istringstream ss(statusLine);
      std::string ver;
      ss >> ver >> r.status;
    }
    std::size_t pos = (lineEnd == std::string::npos) ? head.size() : lineEnd + 2;
    while (pos < head.size())
    {
      std::size_t e = head.find("\r\n", pos);
      if (e == std::string::npos)
      {
        e = head.size();
      }
      std::string line = head.substr(pos, e - pos);
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
        r.body = _buf.substr(0, std::min(len, _buf.size()));
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

RawResponse rawRequest(int port, const std::string &method, const std::string &target,
                       const std::string &extraHeaders = "", const std::string &body = "")
{
  RawConn c;
  REQUIRE(c.open(port));
  c.sendRequest(method, target, extraHeaders, body);
  return c.readResponse(method);
}

int startOn(HttpServer &srv)
{
  int port = nextPort();
  srv.setPort(port);
  srv.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  return port;
}

} // namespace

// ===========================================================================
// task-3.2 — Request inspectors + id-vs-name caveat (AH-9) + L-e trailing-OWS
// ===========================================================================

TEST_CASE("isHtmx detects the literal lowercase 'true' only", "[htmx][inspectors]")
{
  REQUIRE(htmx::isHtmx(makeReq({{"HX-Request", "true"}})) == true);
  REQUIRE(htmx::isHtmx(makeReq({{"HX-Request", "false"}})) == false);
  REQUIRE(htmx::isHtmx(makeReq({})) == false);
  REQUIRE(htmx::isHtmx(makeReq({{"HX-Request", "TRUE"}})) == false);
  REQUIRE(htmx::isHtmx(makeReq({{"HX-Request", "True"}})) == false);
}

TEST_CASE("isBoost detects the literal lowercase 'true' only", "[htmx][inspectors]")
{
  REQUIRE(htmx::isBoost(makeReq({{"HX-Boosted", "true"}})) == true);
  REQUIRE(htmx::isBoost(makeReq({})) == false);
  REQUIRE(htmx::isBoost(makeReq({{"HX-Boosted", "false"}})) == false);
}

TEST_CASE("trigger reads HX-Trigger with present/absent distinction", "[htmx][inspectors]")
{
  REQUIRE(htmx::trigger(makeReq({{"HX-Trigger", "my-btn"}})) == std::optional<std::string>("my-btn"));
  REQUIRE(htmx::trigger(makeReq({})) == std::nullopt);
  REQUIRE(htmx::trigger(makeReq({{"HX-Trigger", ""}})) == std::optional<std::string>(""));
}

TEST_CASE("triggerName reads HX-Trigger-Name with present/absent distinction (AH-9)",
          "[htmx][inspectors]")
{
  REQUIRE(htmx::triggerName(makeReq({{"HX-Trigger-Name", "email"}})) ==
          std::optional<std::string>("email"));
  REQUIRE(htmx::triggerName(makeReq({})) == std::nullopt);
  REQUIRE(htmx::triggerName(makeReq({{"HX-Trigger-Name", ""}})) == std::optional<std::string>(""));
}

TEST_CASE("target reads HX-Target with present/absent distinction", "[htmx][inspectors]")
{
  REQUIRE(htmx::target(makeReq({{"HX-Target", "#list"}})) == std::optional<std::string>("#list"));
  REQUIRE(htmx::target(makeReq({})) == std::nullopt);
  REQUIRE(htmx::target(makeReq({{"HX-Target", ""}})) == std::optional<std::string>(""));
}

TEST_CASE("id-vs-name caveat: trigger()==nullopt does not imply 'no trigger' (AH-9)",
          "[htmx][inspectors][ah9]")
{
  // Element with a name but no id: HTMX sends only HX-Trigger-Name.
  Request nameOnly = makeReq({{"HX-Trigger-Name", "email"}});
  REQUIRE(htmx::trigger(nameOnly) == std::nullopt);
  REQUIRE(htmx::triggerName(nameOnly) == std::optional<std::string>("email"));

  // Element with an id but no name: HTMX sends only HX-Trigger.
  Request idOnly = makeReq({{"HX-Trigger", "save-btn"}});
  REQUIRE(htmx::trigger(idOnly) == std::optional<std::string>("save-btn"));
  REQUIRE(htmx::triggerName(idOnly) == std::nullopt);

  // Element with BOTH an id and a name: HTMX sends BOTH headers (the two are
  // independent, not alternatives).
  Request both = makeReq({{"HX-Trigger", "save-btn"}, {"HX-Trigger-Name", "save"}});
  REQUIRE(htmx::trigger(both) == std::optional<std::string>("save-btn"));
  REQUIRE(htmx::triggerName(both) == std::optional<std::string>("save"));
}

TEST_CASE("L-e: wire-parsed trailing OWS on HX-Request is trimmed by the parser",
          "[htmx][inspectors][wire]")
{
  HttpServer srv;
  srv.onGet("/htmx", [](const Request &req, Response &res)
            { res.set_content(htmx::isHtmx(req) ? "Y" : "N", "text/plain"); });
  int port = startOn(srv);

  // The header value carries a trailing space; parseHeaderLine trims SP/HTAB
  // from the value BEFORE it reaches the map, so isHtmx still matches "true".
  RawResponse r = rawRequest(port, "GET", "/htmx", "HX-Request: true \r\n");
  REQUIRE(r.status == 200);
  REQUIRE(r.body == "Y");

  // Sanity: a genuinely-different value is not matched.
  RawResponse r2 = rawRequest(port, "GET", "/htmx", "HX-Request: nope\r\n");
  REQUIRE(r2.status == 200);
  REQUIRE(r2.body == "N");

  srv.stop();
}

TEST_CASE("L-5: a wire-sent present-but-empty HX-Trigger arrives as present (not absent)",
          "[htmx][inspectors][wire]")
{
  HttpServer srv;
  // Encode the present/absent distinction over a real wire request: 'P' present,
  // 'E' present-empty, 'A' absent.
  srv.onGet("/trig", [](const Request &req, Response &res)
            {
              auto t = htmx::trigger(req);
              const char *r = !t.has_value() ? "A" : (t->empty() ? "E" : "P");
              res.set_content(r, "text/plain");
            });
  int port = startOn(srv);

  // Header sent with an empty value: parseHeaderLine stores key with value "",
  // so has_header is true -> trigger() == optional("").
  RawResponse empty = rawRequest(port, "GET", "/trig", "HX-Trigger:\r\n");
  REQUIRE(empty.status == 200);
  REQUIRE(empty.body == "E");

  // Header absent -> nullopt.
  RawResponse absent = rawRequest(port, "GET", "/trig");
  REQUIRE(absent.status == 200);
  REQUIRE(absent.body == "A");

  // Header with a value -> present non-empty.
  RawResponse present = rawRequest(port, "GET", "/trig", "HX-Trigger: my-btn\r\n");
  REQUIRE(present.status == 200);
  REQUIRE(present.body == "P");

  srv.stop();
}

// ===========================================================================
// task-3.3 — Case-insensitive header lookup (M-R4 VERIFIED)
// ===========================================================================

TEST_CASE("case-insensitive lookup: lowercase-stored headers are still detected (M-R4)",
          "[htmx][inspectors][caseinsensitive]")
{
  // Headers stored under lowercase keys; the helpers pass canonical 'HX-*' and
  // rely on the HttpHeaders map's case-insensitive comparator (asciiLower).
  Request req = makeReq({{"hx-request", "true"},
                         {"hx-trigger-name", "email"},
                         {"hx-target", "#list"},
                         {"hx-boosted", "true"}});
  REQUIRE(htmx::isHtmx(req) == true);
  REQUIRE(htmx::isBoost(req) == true);
  REQUIRE(htmx::triggerName(req) == std::optional<std::string>("email"));
  REQUIRE(htmx::target(req) == std::optional<std::string>("#list"));
}

// ===========================================================================
// task-3.4 — Response setter round-trips + exact spelling + L-f escaped-\n
// ===========================================================================

TEST_CASE("response setters round-trip values under the exact HX-* keys", "[htmx][setters]")
{
  Response res;
  htmx::setRedirect(res, "https://example.com/x");
  htmx::setRefresh(res);
  htmx::setPushUrl(res, "/admin/routes/42");
  htmx::setRetarget(res, "#error-box");
  htmx::setReswap(res, "beforeend");
  htmx::setTrigger(res, "saved");

  REQUIRE(headerValue(res, "HX-Redirect") == "https://example.com/x");
  REQUIRE(headerValue(res, "HX-Refresh") == "true");
  REQUIRE(headerValue(res, "HX-Push-Url") == "/admin/routes/42");
  REQUIRE(headerValue(res, "HX-Retarget") == "#error-box");
  REQUIRE(headerValue(res, "HX-Reswap") == "beforeend");
  REQUIRE(headerValue(res, "HX-Trigger") == "saved");
}

TEST_CASE("exact header-name spelling: HX-Push-Url, not HX-PushUrl", "[htmx][setters][spelling]")
{
  Response res;
  htmx::setPushUrl(res, "/x");
  REQUIRE(hasHeader(res, "HX-Push-Url") == true);
  REQUIRE(hasHeader(res, "HX-PushUrl") == false);
}

TEST_CASE("setPushUrl writes the literal 'false' through (history suppression)",
          "[htmx][setters]")
{
  Response res;
  htmx::setPushUrl(res, "false");
  REQUIRE(headerValue(res, "HX-Push-Url") == "false");
}

TEST_CASE("setTrigger writes a pre-serialized JSON object verbatim", "[htmx][setters]")
{
  Response res;
  htmx::setTrigger(res, "{\"showMessage\":\"ok\"}");
  REQUIRE(headerValue(res, "HX-Trigger") == "{\"showMessage\":\"ok\"}");
}

TEST_CASE("L-f: setTrigger accepts a JSON-escaped backslash-n (not a raw newline)",
          "[htmx][setters][crlf]")
{
  // The two-byte escape sequence backslash + 'n' (0x5C 0x6E) is NOT a raw LF.
  const std::string json = "{\"msg\":\"line1\\nline2\"}";
  Response res;
  REQUIRE_NOTHROW(htmx::setTrigger(res, json));
  REQUIRE(headerValue(res, "HX-Trigger") == json);
}

// ===========================================================================
// task-3.5 — CR/LF rejection (M-8) + negative control + unmodified-on-throw
// ===========================================================================

TEST_CASE("M-8: setRedirect rejects CR/LF and writes no header", "[htmx][crlf][m8]")
{
  Response res;
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "http://x/\r\nSet-Cookie: evil=1"),
                    std::invalid_argument);
  REQUIRE(hasHeader(res, "HX-Redirect") == false);
}

TEST_CASE("M-8: CR and LF are independently rejected", "[htmx][crlf][m8]")
{
  Response res;
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "http://x/\ninjected"), std::invalid_argument);
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "http://x/\rinjected"), std::invalid_argument);
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "http://x/\r\ninjected"), std::invalid_argument);
  REQUIRE(hasHeader(res, "HX-Redirect") == false);
}

TEST_CASE("M-8: all value-taking setters reject CR/LF", "[htmx][crlf][m8]")
{
  {
    Response res;
    REQUIRE_THROWS_AS(htmx::setPushUrl(res, "/x\r\ninjected"), std::invalid_argument);
    REQUIRE(hasHeader(res, "HX-Push-Url") == false);
  }
  {
    Response res;
    REQUIRE_THROWS_AS(htmx::setRetarget(res, "#x\r\ninjected"), std::invalid_argument);
    REQUIRE(hasHeader(res, "HX-Retarget") == false);
  }
  {
    Response res;
    REQUIRE_THROWS_AS(htmx::setReswap(res, "innerHTML\ninjected"), std::invalid_argument);
    REQUIRE(hasHeader(res, "HX-Reswap") == false);
  }
  {
    Response res;
    REQUIRE_THROWS_AS(htmx::setTrigger(res, "{\"e\":\"x\"}\r\ninjected"), std::invalid_argument);
    REQUIRE(hasHeader(res, "HX-Trigger") == false);
  }
}

TEST_CASE("M-8 negative control: clean values with punctuation are accepted", "[htmx][crlf][m8]")
{
  Response res;
  REQUIRE_NOTHROW(htmx::setRedirect(res, "https://h/p?a=1&b=2#frag"));
  REQUIRE(headerValue(res, "HX-Redirect") == "https://h/p?a=1&b=2#frag");
  REQUIRE_NOTHROW(htmx::setRetarget(res, "#box .row > a[data-x='1']"));
  REQUIRE(headerValue(res, "HX-Retarget") == "#box .row > a[data-x='1']");
}

TEST_CASE("M-8: a throwing setter leaves the Response unmodified for that header",
          "[htmx][crlf][m8]")
{
  Response res;
  res.set_header("HX-Redirect", "preexisting");
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "x\r\ny"), std::invalid_argument);
  // The rejecting setter throws before set_header, so the prior value is intact
  // (the helper does not partially mutate).
  REQUIRE(headerValue(res, "HX-Redirect") == "preexisting");
}

// ===========================================================================
// task-3.7 — Dangerous-scheme rejection (M-B) + negatives + boundaries
// ===========================================================================

TEST_CASE("M-B: setRedirect/setPushUrl reject javascript:/data:/vbscript:", "[htmx][scheme][mb]")
{
  for (const std::string bad : {"javascript:alert(1)", "data:text/html,<script>x</script>",
                                "vbscript:msgbox(1)"})
  {
    Response a;
    REQUIRE_THROWS_AS(htmx::setRedirect(a, bad), std::invalid_argument);
    REQUIRE(hasHeader(a, "HX-Redirect") == false);
    Response b;
    REQUIRE_THROWS_AS(htmx::setPushUrl(b, bad), std::invalid_argument);
    REQUIRE(hasHeader(b, "HX-Push-Url") == false);
  }
}

TEST_CASE("M-B: dangerous-scheme match is case-insensitive", "[htmx][scheme][mb]")
{
  Response res;
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "JavaScript:alert(1)"), std::invalid_argument);
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "JAVASCRIPT:alert(1)"), std::invalid_argument);
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "DATA:text/html,x"), std::invalid_argument);
}

TEST_CASE("M-B: scheme obfuscation via leading whitespace and embedded TAB is caught",
          "[htmx][scheme][mb]")
{
  Response res;
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "  javascript:alert(1)"), std::invalid_argument);
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "\t javascript:alert(1)"), std::invalid_argument);
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "java\tscript:alert(1)"), std::invalid_argument);
  // Leading C0 control (0x01, <= 0x20) is skipped before the scheme, then the
  // dangerous scheme is detected. No embedded NUL, so the single-arg ctor is fine.
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "\x01javascript:alert(1)"), std::invalid_argument);
  // Combined TAB-skip + uppercase fold in one value.
  REQUIRE_THROWS_AS(htmx::setRedirect(res, "java\tSCRIPT:alert(1)"), std::invalid_argument);

  // setPushUrl routes through the same guard — parity for the obfuscation paths.
  Response p;
  REQUIRE_THROWS_AS(htmx::setPushUrl(p, "  javascript:alert(1)"), std::invalid_argument);
  REQUIRE_THROWS_AS(htmx::setPushUrl(p, "java\tscript:alert(1)"), std::invalid_argument);
  REQUIRE_THROWS_AS(htmx::setPushUrl(p, "JavaScript:alert(1)"), std::invalid_argument);
  REQUIRE(hasHeader(p, "HX-Push-Url") == false);
}

TEST_CASE("M-B negative controls: scheme-clean values are accepted", "[htmx][scheme][mb]")
{
  const std::initializer_list<std::string> ok = {
    "https://example.com/x", "/admin/routes/42", "#section", "data-driven/path",
    "javascript-foo:bar",    "javascript",       "mailto:a@b.com", "tel:+15551234"};
  for (const std::string &v : ok)
  {
    Response res;
    REQUIRE_NOTHROW(htmx::setRedirect(res, v));
    REQUIRE(headerValue(res, "HX-Redirect") == v);
  }
  // setPushUrl 'false' (no scheme) is accepted too.
  Response p;
  REQUIRE_NOTHROW(htmx::setPushUrl(p, "false"));
  REQUIRE(headerValue(p, "HX-Push-Url") == "false");
}

TEST_CASE("M-B / cpp-L1: embedded NUL or other C0 control terminates the scheme run (accepted)",
          "[htmx][scheme][mb]")
{
  // Only TAB is ignored mid-scheme; an interior 0x01 or NUL terminates the run
  // (no ':' found -> no scheme), matching WHATWG URL parsing. A browser would
  // not parse these as the javascript scheme either.
  const std::string c0 = std::string("java\x01script:alert(1)");
  // Explicit length 20 captures the interior NUL without the literal's implicit
  // trailing terminator: "java"(4) + NUL(1) + "script:alert(1)"(15) = 20.
  const std::string nul = std::string("java\x00script:alert(1)", 20);
  Response a;
  REQUIRE_NOTHROW(htmx::setRedirect(a, c0));
  REQUIRE(headerValue(a, "HX-Redirect") == c0);
  Response b;
  REQUIRE_NOTHROW(htmx::setRedirect(b, nul));
  REQUIRE(headerValue(b, "HX-Redirect") == nul);
}

TEST_CASE("M-B open-redirect scope lock: a scheme-clean cross-origin URL is accepted",
          "[htmx][scheme][mb][openredirect]")
{
  // DD-8 scope boundary: the guard rejects dangerous SCHEMES only, NOT
  // same-origin/open-redirect. This conscious acceptance is asserted so the
  // omission stays deliberate (the handler owns origin policy).
  Response res;
  REQUIRE_NOTHROW(htmx::setRedirect(res, "https://evil.example/phish"));
  REQUIRE(headerValue(res, "HX-Redirect") == "https://evil.example/phish");
}

TEST_CASE("M-B: setRetarget/setReswap/setTrigger are NOT scheme-validated", "[htmx][scheme][mb]")
{
  // A CSS selector / swap token / event value is not a navigable URL; only CR/LF
  // applies to them.
  Response res;
  REQUIRE_NOTHROW(htmx::setRetarget(res, "javascript:foo"));
  REQUIRE(headerValue(res, "HX-Retarget") == "javascript:foo");
  REQUIRE_NOTHROW(htmx::setReswap(res, "javascript:foo"));
  REQUIRE_NOTHROW(htmx::setTrigger(res, "javascript:foo"));
}

// ===========================================================================
// task-3.6 — L-3: request-derived bad value -> 500 via the routing safety net
// ===========================================================================

TEST_CASE("L-3: a request-derived CR/LF or dangerous-scheme value yields 500, no HX-Redirect",
          "[htmx][l3][safetynet]")
{
  HttpServer srv;
  // The handler echoes the request body (request-derived) into setRedirect.
  srv.onPost("/echo-redirect", [](const Request &req, Response &res)
             {
               htmx::setRedirect(res, req.body);
               res.set_content("OK", "text/plain");
             });
  int port = startOn(srv);

  // Positive control: a clean URL succeeds and the HX-Redirect header is set.
  RawResponse okResp = rawRequest(port, "POST", "/echo-redirect", "", "https://ok.example/next");
  REQUIRE(okResp.status == 200);
  REQUIRE(okResp.header("hx-redirect") == "https://ok.example/next");

  // CR/LF in a request-derived value: setRedirect throws -> safety net -> 500.
  RawResponse crlf = rawRequest(port, "POST", "/echo-redirect", "",
                                "http://x/\r\nSet-Cookie: evil=1");
  REQUIRE(crlf.status == 500);
  REQUIRE(crlf.hasHeader("hx-redirect") == false);

  // Dangerous scheme in a request-derived value: same throw -> 500 path.
  RawResponse scheme = rawRequest(port, "POST", "/echo-redirect", "", "javascript:alert(1)");
  REQUIRE(scheme.status == 500);
  REQUIRE(scheme.hasHeader("hx-redirect") == false);

  srv.stop();
}
