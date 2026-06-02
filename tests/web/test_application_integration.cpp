// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// End-to-end integration tests for iora::web::Application (HTMX phase 8).
// Architecture: coding_trackers/architecture/iora/application_wiring.json (R4).
// Tracker: 2026-05-29-9 (htmx-support phase 8 application-wiring).
//
// Real-socket integration: a real HttpServer on 127.0.0.1:<free_port>, a real
// core::TimerService, a real Assets (embedded or temp dir), a real Application,
// driven over raw TCP. ctest runs -j1 (web tests share ports).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include <iora/web/application.hpp>

using iora::network::HttpServer;
using iora::web::Application;
using iora::web::Assets;
using iora::web::EmbeddedAsset;
using iora::web::EmbeddedAssetRegistry;
using iora::web::EmbeddedTemplate;
using iora::web::SseChannel;
using Request = HttpServer::Request;
using Response = HttpServer::Response;
namespace parsers = iora::parsers;
namespace core = iora::core;

// Application is non-copyable AND non-movable (owns SseManager + ConcurrentHashMap
// + reference members) — cpp17 L-4.
static_assert(!std::is_copy_constructible<Application>::value, "non-copyable");
static_assert(!std::is_move_constructible<Application>::value, "non-movable");

namespace
{
using namespace std::chrono_literals;

std::atomic<int> g_nextPort{19400};
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
  return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

template <typename Pred> bool waitFor(Pred pred, int timeoutMs = 5000)
{
  auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  while (!pred())
  {
    if (std::chrono::steady_clock::now() > deadline)
    {
      return false;
    }
    std::this_thread::sleep_for(10ms);
  }
  return true;
}

// ── Embedded asset registry (file-scope so it outlives every Assets) ─────────

constexpr std::string_view kCssBytes = "body{color:red}";
constexpr std::string_view kCssEtag = "csstag0001";
constexpr std::string_view kJsBytes = "console.log(1)";
constexpr std::string_view kJsEtag = "jstag0001";
constexpr std::string_view kJsGzip = "GZIP-BYTES-OF-JS"; // opaque gzip variant payload
constexpr std::string_view kJsGzipEtag = "jsgztag0001";
constexpr std::string_view kSvgBytes = "<svg xmlns='http://www.w3.org/2000/svg'></svg>";
constexpr std::string_view kSvgEtag = "svgtag0001";
constexpr std::string_view kDocBytes = "<html><body>doc</body></html>";
constexpr std::string_view kDocEtag = "doctag0001";

// sorted by path (ASCII)
const EmbeddedAsset kStatics[] = {
  {"app.css", kCssBytes, kCssEtag, std::nullopt, {}},
  {"app.js", kJsBytes, kJsEtag, std::optional<std::string_view>(kJsGzip), kJsGzipEtag},
  {"doc.html", kDocBytes, kDocEtag, std::nullopt, {}},
  {"icon.svg", kSvgBytes, kSvgEtag, std::nullopt, {}},
};

constexpr std::string_view kBadPartialTpl = "{{>missing}}";
constexpr std::string_view kFormTpl = "<p>{{msg}}</p>";
constexpr std::string_view kFragTpl = "<tr><td>{{name}}</td></tr>";
constexpr std::string_view kPageTpl = "<!doctype html><html><body><h1>{{title}}</h1></body></html>";
constexpr std::string_view kRowTpl = "<li>{{item}}</li>";
constexpr std::string_view kWithPartialTpl = "<ul>{{>row}}</ul>";

// sorted by name (ASCII)
const EmbeddedTemplate kTemplates[] = {
  {"badpartial.html", kBadPartialTpl}, {"form.html", kFormTpl},
  {"frag.html", kFragTpl},             {"page.html", kPageTpl},
  {"row", kRowTpl},                    {"withpartial.html", kWithPartialTpl},
};

// Temp filesystem tree for fromDirectory tests (root/templates, root/static).
struct TempTree
{
  std::filesystem::path root;
  explicit TempTree(const std::string &tag)
  {
    root = std::filesystem::temp_directory_path() /
           ("iora_app_" + tag + "_" + std::to_string(nextPort()));
    std::filesystem::create_directories(root / "templates");
    std::filesystem::create_directories(root / "static");
  }
  ~TempTree()
  {
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
  }
  void writeStatic(const std::string &rel, const std::string &content)
  {
    std::ofstream(root / "static" / rel, std::ios::trunc) << content;
  }
  void writeTemplate(const std::string &rel, const std::string &content)
  {
    std::ofstream(root / "templates" / rel, std::ios::trunc) << content;
  }
};

const EmbeddedAssetRegistry kRegistry = [] {
  EmbeddedAssetRegistry r;
  r.templates = kTemplates;
  r.templatesCount = sizeof(kTemplates) / sizeof(kTemplates[0]);
  r.statics = kStatics;
  r.staticsCount = sizeof(kStatics) / sizeof(kStatics[0]);
  return r;
}();

// ── Raw HTTP/1.1 client (normal requests + SSE streaming) ────────────────────

struct RawResponse
{
  bool ok = false;
  int status = 0;
  std::map<std::string, std::string> headers; // lowercased keys
  std::string body;
  std::string rawHead;

  bool hasHeader(const std::string &k) const { return headers.count(lower(k)) > 0; }
  std::string header(const std::string &k) const
  {
    auto it = headers.find(lower(k));
    return it == headers.end() ? "" : it->second;
  }
};

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
    if (::connect(_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
    {
      ::close(_fd);
      _fd = -1;
      return false;
    }
    return true;
  }

  ~Conn() { closeFd(); }

  void closeFd()
  {
    if (_fd >= 0)
    {
      ::close(_fd);
      _fd = -1;
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

  std::string readSome()
  {
    char tmp[4096];
    ssize_t n = ::recv(_fd, tmp, sizeof(tmp), 0);
    if (n <= 0)
    {
      return "";
    }
    return std::string(tmp, static_cast<std::size_t>(n));
  }

  // Stream read until `needle` appears (SSE) or timeout.
  std::string readUntil(const std::string &needle, int maxMs = 3000)
  {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(maxMs);
    while (_acc.find(needle) == std::string::npos)
    {
      if (std::chrono::steady_clock::now() > deadline)
      {
        break;
      }
      std::string chunk = readSome();
      if (chunk.empty())
      {
        if (std::chrono::steady_clock::now() > deadline)
        {
          break;
        }
        continue;
      }
      _acc += chunk;
    }
    return _acc;
  }

  RawResponse readResponse(const std::string &method)
  {
    RawResponse r;
    std::size_t hdrEnd;
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
  std::string _acc;
};

RawResponse rawRequest(int port, const std::string &method, const std::string &target,
                       const std::string &extraHeaders = "", const std::string &body = "")
{
  Conn c;
  REQUIRE(c.open(port));
  c.sendRequest(method, target, extraHeaders, body, false);
  return c.readResponse(method);
}

// ── Fixture: HttpServer + TimerService + embedded Assets + Application ────────
// Declaration order (assets, timer, srv, app) gives safe reverse destruction:
// app -> srv (stop drains) -> timer -> assets, so the HTTP drain completes
// before Assets is destroyed (APP-7) and the TimerService outlives the manager.

struct AppFixture
{
  Assets assets;
  core::TimerService timer;
  HttpServer srv;
  Application app;
  int port;

  explicit AppFixture(std::chrono::milliseconds heartbeat = 15000ms)
      : assets(Assets::fromEmbedded(kRegistry)), app(srv, assets, timer, heartbeat),
        port(nextPort())
  {
    timer.start();
    srv.setPort(port);
  }

  void start()
  {
    srv.start();
    std::this_thread::sleep_for(300ms);
  }

  ~AppFixture()
  {
    app.shutdown();
    srv.stop();
    timer.stop();
  }
};

// Find the numeric value on a Prometheus line whose key starts with `metricName`.
std::optional<double> prometheusValue(const std::string &text, const std::string &metricName)
{
  std::istringstream ss(text);
  std::string line;
  while (std::getline(ss, line))
  {
    if (line.rfind(metricName, 0) == 0 && (line.size() == metricName.size() ||
                                           line[metricName.size()] == '{' ||
                                           line[metricName.size()] == ' '))
    {
      std::size_t sp = line.find_last_of(' ');
      if (sp != std::string::npos)
      {
        try
        {
          return std::stod(line.substr(sp + 1));
        }
        catch (...)
        {
          return std::nullopt;
        }
      }
    }
  }
  return std::nullopt;
}

} // namespace

// ===========================================================================
// task-8.5.2 — page / fragment / postFragment, escaping, dev/prod 500, render
// ===========================================================================

TEST_CASE("page() renders a full document with HTML-escaped values", "[application][page]")
{
  AppFixture fx;
  fx.app.page("/page", "page.html",
              [](const Request &, Response &, parsers::Json &data)
              { data["title"] = parsers::Json("a<b>c"); });
  fx.start();

  RawResponse r = rawRequest(fx.port, "GET", "/page");
  REQUIRE(r.status == 200);
  REQUIRE(r.header("content-type") == "text/html; charset=utf-8");
  REQUIRE(r.body.find("<!doctype html>") != std::string::npos);
  REQUIRE(r.body.find("a&lt;b&gt;c") != std::string::npos); // escaped
  REQUIRE(r.body.find("a<b>c") == std::string::npos);
}

TEST_CASE("fragment() renders a bare fragment", "[application][fragment]")
{
  AppFixture fx;
  fx.app.fragment("/frag", "frag.html",
                  [](const Request &, Response &, parsers::Json &data)
                  { data["name"] = parsers::Json("Bob"); });
  fx.start();

  RawResponse r = rawRequest(fx.port, "GET", "/frag");
  REQUIRE(r.status == 200);
  REQUIRE(r.header("content-type") == "text/html; charset=utf-8");
  REQUIRE(r.body == "<tr><td>Bob</td></tr>");
  REQUIRE(r.body.find("<html>") == std::string::npos);
}

TEST_CASE("postFragment() parses the form and supports HTMX-swap-on-error", "[application][post]")
{
  AppFixture fx;
  fx.app.postFragment("/save", "form.html",
                      [](const std::unordered_map<std::string, std::string> &form, Response &res,
                         parsers::Json &data)
                      {
                        auto it = form.find("name");
                        if (it == form.end() || it->second.empty())
                        {
                          res.status = 400;
                          data["msg"] = parsers::Json("required");
                          return;
                        }
                        data["msg"] = parsers::Json(it->second);
                      });
  fx.start();

  RawResponse ok = rawRequest(fx.port, "POST", "/save",
                              "Content-Type: application/x-www-form-urlencoded\r\n", "name=hi");
  REQUIRE(ok.status == 200);
  REQUIRE(ok.body == "<p>hi</p>");

  // Validation error: FormHandler sets 400, render succeeds -> error fragment body.
  RawResponse bad = rawRequest(fx.port, "POST", "/save",
                               "Content-Type: application/x-www-form-urlencoded\r\n", "name=");
  REQUIRE(bad.status == 400);
  REQUIRE(bad.body == "<p>required</p>");
}

TEST_CASE("render() injects the Assets-backed PartialResolver; throws on failure", "[application][render]")
{
  AppFixture fx;
  parsers::Json data;
  data["item"] = parsers::Json("X");
  REQUIRE(fx.app.render("withpartial.html", data) == "<ul><li>X</li></ul>");
  // Missing top-level template throws (no status, no body).
  REQUIRE_THROWS_AS(fx.app.render("nope.html", data), parsers::MustacheError);
  // Missing partial -> Mustache throws.
  REQUIRE_THROWS_AS(fx.app.render("badpartial.html", data), parsers::MustacheError);
}

TEST_CASE("dev/prod 500 bodies differ for the identical failing request (OQ-5)", "[application][devmode]")
{
  AppFixture fx;
  fx.app.page("/broken", "nope.html", [](const Request &, Response &, parsers::Json &) {});
  fx.start();

  RawResponse prod = rawRequest(fx.port, "GET", "/broken");
  REQUIRE(prod.status == 500);
  REQUIRE(prod.body == "Internal Server Error");

  fx.app.setDevMode(true);
  RawResponse dev = rawRequest(fx.port, "GET", "/broken");
  REQUIRE(dev.status == 500);
  REQUIRE(dev.body.find("nope.html") != std::string::npos);
  REQUIRE(dev.body != prod.body);
}

TEST_CASE("page route registered with a temporary string still routes (RD-25 by-value capture)",
          "[application][capture]")
{
  AppFixture fx;
  {
    std::string ephemeralPath = "/temp-path";
    std::string ephemeralTpl = "page.html";
    fx.app.page(ephemeralPath, ephemeralTpl,
                [](const Request &, Response &, parsers::Json &data)
                { data["title"] = parsers::Json("ok"); });
  } // ephemeral strings destroyed here; the handler must have copied them
  fx.start();

  RawResponse r = rawRequest(fx.port, "GET", "/temp-path");
  REQUIRE(r.status == 200);
  REQUIRE(r.body.find("<h1>ok</h1>") != std::string::npos);
}

// ===========================================================================
// task-8.5.3 — serveStatic
// ===========================================================================

TEST_CASE("serveStatic happy path: RD-4 headers (ETag, Cache-Control, nosniff)", "[application][static]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();

  RawResponse r = rawRequest(fx.port, "GET", "/static/app.css");
  REQUIRE(r.status == 200);
  REQUIRE(r.body == std::string(kCssBytes));
  REQUIRE(r.header("content-type") == "text/css");
  REQUIRE(r.header("etag") == "\"csstag0001\""); // quoted strong, no W/
  REQUIRE(r.header("cache-control") == "public, max-age=3600");
  REQUIRE(r.header("x-content-type-options") == "nosniff");
  REQUIRE(r.header("vary").empty()); // no gzip variant -> no Vary
}

TEST_CASE("serveStatic 304 via direct field writes (RD-21): no body, Content-Length 0",
          "[application][static][304]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();

  RawResponse r = rawRequest(fx.port, "GET", "/static/app.css",
                             "If-None-Match: \"csstag0001\"\r\n");
  REQUIRE(r.status == 304);
  REQUIRE(r.body.empty());
  // RFC 9110 §15.4.5: Content-Length MUST be omitted on this 304 (the 200 body
  // is non-empty, so "0" would be non-compliant). Proves direct-write + the
  // pre-seeded body-framing headers were stripped (RD-21), not set_content.
  REQUIRE_FALSE(r.hasHeader("content-length"));
  REQUIRE_FALSE(r.hasHeader("content-type")); // stale text/plain stripped too
  REQUIRE(r.header("etag") == "\"csstag0001\"");
  REQUIRE(r.header("cache-control") == "public, max-age=3600");
  REQUIRE(r.header("x-content-type-options") == "nosniff");
  REQUIRE_FALSE(r.hasHeader("content-encoding"));
}

TEST_CASE("serveStatic If-None-Match comma-list / '*' / weak comparison (RD-4)",
          "[application][static][inm]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();

  REQUIRE(rawRequest(fx.port, "GET", "/static/app.css",
                     "If-None-Match: \"x\", \"csstag0001\", \"y\"\r\n")
            .status == 304);
  REQUIRE(rawRequest(fx.port, "GET", "/static/app.css", "If-None-Match: *\r\n").status == 304);
  REQUIRE(rawRequest(fx.port, "GET", "/static/app.css",
                     "If-None-Match: W/\"csstag0001\"\r\n")
            .status == 304); // weak compare strips W/
  REQUIRE(rawRequest(fx.port, "GET", "/static/app.css", "If-None-Match: \"nope\"\r\n").status == 200);
}

TEST_CASE("serveStatic Accept-Encoding q-values (web L-1): gzip;q=0 -> identity",
          "[application][static][qvalue]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();

  // gzip;q=0 explicit refusal -> identity 200 (rawEtag, no Content-Encoding).
  RawResponse id = rawRequest(fx.port, "GET", "/static/app.js", "Accept-Encoding: gzip;q=0\r\n");
  REQUIRE(id.status == 200);
  REQUIRE(id.body == std::string(kJsBytes));
  REQUIRE(id.header("etag") == "\"jstag0001\"");
  REQUIRE_FALSE(id.hasHeader("content-encoding"));

  // Companion: identity-cached client revalidates with q=0 -> 304 against rawEtag.
  RawResponse rev = rawRequest(fx.port, "GET", "/static/app.js",
                               "Accept-Encoding: gzip;q=0\r\nIf-None-Match: \"jstag0001\"\r\n");
  REQUIRE(rev.status == 304);
  REQUIRE(rev.header("etag") == "\"jstag0001\"");
}

TEST_CASE("serveStatic Accept-Encoding negotiation branches (web L-1 / RFC 9110 §12.5.3)",
          "[application][static][qvalue]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();
  auto isGzip = [&](const std::string &ae)
  {
    RawResponse r =
      rawRequest(fx.port, "GET", "/static/app.js", ae.empty() ? "" : ("Accept-Encoding: " + ae + "\r\n"));
    return r.header("content-encoding") == "gzip";
  };
  REQUIRE(isGzip("gzip"));                  // bare token = q=1
  REQUIRE(isGzip("*"));                      // wildcard enables gzip
  REQUIRE(isGzip("identity, gzip"));         // multi-entry, gzip present
  REQUIRE(isGzip("gzip;q=0.5, *;q=0"));      // explicit gzip (q>0) wins over *;q=0
  REQUIRE(isGzip("gzip; q=1"));              // OWS after ';'
  REQUIRE_FALSE(isGzip(""));                 // absent -> identity
  REQUIRE_FALSE(isGzip("gzip;q=0"));         // explicit refusal
  REQUIRE_FALSE(isGzip("*;q=0"));            // wildcard refusal
  REQUIRE_FALSE(isGzip("gzip;q=0, *;q=1"));  // explicit gzip;q=0 overrides *;q=1
  REQUIRE_FALSE(isGzip("identity"));         // gzip not listed, no *
  REQUIRE_FALSE(isGzip("gzip;q=abc"));       // malformed q -> not acceptable
  REQUIRE_FALSE(isGzip("gzip;q=1.5"));       // out-of-range -> not acceptable
}

TEST_CASE("serveStatic gzip representation: select-then-compare 304 (web M-1)",
          "[application][static][gzip]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();

  // gzip served -> gzipEtag + Content-Encoding + Vary.
  RawResponse gz = rawRequest(fx.port, "GET", "/static/app.js", "Accept-Encoding: gzip\r\n");
  REQUIRE(gz.status == 200);
  REQUIRE(gz.body == std::string(kJsGzip));
  REQUIRE(gz.header("etag") == "\"jsgztag0001\"");
  REQUIRE(gz.header("content-encoding") == "gzip");
  REQUIRE(gz.header("vary") == "Accept-Encoding");

  // Revalidate gzip rep -> 304 with the gzip ETag + Vary, no Content-Encoding, no body.
  RawResponse gz304 = rawRequest(fx.port, "GET", "/static/app.js",
                                 "Accept-Encoding: gzip\r\nIf-None-Match: \"jsgztag0001\"\r\n");
  REQUIRE(gz304.status == 304);
  REQUIRE(gz304.body.empty());
  REQUIRE(gz304.header("etag") == "\"jsgztag0001\"");
  REQUIRE(gz304.header("vary") == "Accept-Encoding");
  REQUIRE_FALSE(gz304.hasHeader("content-encoding"));

  // SYMMETRIC: identity revalidation without gzip -> 304 against rawEtag.
  REQUIRE(rawRequest(fx.port, "GET", "/static/app.js", "If-None-Match: \"jstag0001\"\r\n").status ==
          304);

  // CROSS: If-None-Match rawEtag WITH gzip -> server selects gzip, compares gzipEtag,
  // no match -> 200 gzip (NOT a spurious 304 against rawEtag).
  RawResponse cross = rawRequest(fx.port, "GET", "/static/app.js",
                                 "Accept-Encoding: gzip\r\nIf-None-Match: \"jstag0001\"\r\n");
  REQUIRE(cross.status == 200);
  REQUIRE(cross.header("etag") == "\"jsgztag0001\"");
}

TEST_CASE("serveStatic per-representation ETag (M-f): identity vs gzip differ",
          "[application][static][etag]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();
  std::string id = rawRequest(fx.port, "GET", "/static/app.js").header("etag");
  std::string gz =
    rawRequest(fx.port, "GET", "/static/app.js", "Accept-Encoding: gzip\r\n").header("etag");
  REQUIRE(id == "\"jstag0001\"");
  REQUIRE(gz == "\"jsgztag0001\"");
  REQUIRE(id != gz);
}

TEST_CASE("serveStatic Vary advertised even when identity served (AC-2)", "[application][static][vary]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();
  // No Accept-Encoding -> identity bytes, but a gzip variant exists -> still Vary.
  RawResponse r = rawRequest(fx.port, "GET", "/static/app.js");
  REQUIRE(r.status == 200);
  REQUIRE(r.body == std::string(kJsBytes));
  REQUIRE(r.header("vary") == "Accept-Encoding");
  REQUIRE_FALSE(r.hasHeader("content-encoding"));
}

TEST_CASE("serveStatic security headers: nosniff + CSP sandbox for SVG and HTML (web H-1)",
          "[application][static][security]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();

  RawResponse svg = rawRequest(fx.port, "GET", "/static/icon.svg");
  REQUIRE(svg.status == 200);
  REQUIRE(svg.header("content-type") == "image/svg+xml");
  REQUIRE(svg.header("x-content-type-options") == "nosniff");
  REQUIRE(svg.header("content-security-policy") == "sandbox");

  RawResponse html = rawRequest(fx.port, "GET", "/static/doc.html");
  REQUIRE(html.status == 200);
  REQUIRE(html.header("content-type") == "text/html; charset=utf-8");
  REQUIRE(html.header("content-security-policy") == "sandbox");

  // 304 carries nosniff but no CSP (delivered with the 200 body).
  RawResponse svg304 = rawRequest(fx.port, "GET", "/static/icon.svg",
                                  "If-None-Match: \"svgtag0001\"\r\n");
  REQUIRE(svg304.status == 304);
  REQUIRE(svg304.header("x-content-type-options") == "nosniff");
  REQUIRE_FALSE(svg304.hasHeader("content-security-policy"));

  // A CSS 200 carries no CSP (not an active-content type).
  REQUIRE(rawRequest(fx.port, "GET", "/static/app.css").hasHeader("content-security-policy") ==
          false);
}

TEST_CASE("serveStatic security headers on a FILESYSTEM (operator-supplied) SVG/HTML (web H-1)",
          "[application][static][security][filesystem]")
{
  // RD-11 EXTERNAL_DIR sink: tenant/operator-supplied files served from disk are
  // the acute SVG stored-XSS case the nosniff+CSP mitigation targets.
  TempTree tree("sec");
  tree.writeStatic("evil.svg", "<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>");
  tree.writeStatic("op.html", "<html><body>hi</body></html>");
  Assets assets = Assets::fromDirectory(tree.root);
  core::TimerService timer;
  timer.start();
  HttpServer srv;
  int port = nextPort();
  srv.setPort(port);
  Application app(srv, assets, timer);
  app.serveStatic("/static/");
  srv.start();
  std::this_thread::sleep_for(300ms);

  RawResponse svg = rawRequest(port, "GET", "/static/evil.svg");
  REQUIRE(svg.status == 200);
  REQUIRE(svg.header("content-type") == "image/svg+xml");
  REQUIRE(svg.header("x-content-type-options") == "nosniff");
  REQUIRE(svg.header("content-security-policy") == "sandbox");

  RawResponse html = rawRequest(port, "GET", "/static/op.html");
  REQUIRE(html.status == 200);
  REQUIRE(html.header("content-security-policy") == "sandbox");

  app.shutdown();
  srv.stop();
  timer.stop();
}

TEST_CASE("serveStatic tri-state + OQ-9 pre-check + miss", "[application][static][traversal]")
{
  AppFixture fx;
  fx.app.serveStatic("/static/");
  fx.start();

  // OQ-9 pre-check (literal and percent-encoded ..) -> 400.
  REQUIRE(rawRequest(fx.port, "GET", "/static/../etc/passwd").status == 400);
  REQUIRE(rawRequest(fx.port, "GET", "/static/%2e%2e%2fetc").status == 400); // decoded -> ".."
  // Canonical-rejection backstop: a backslash slips past the cheap pre-check
  // (which only looks for ".." / leading "/") but getStatic returns Rejected -> 400.
  REQUIRE(rawRequest(fx.port, "GET", "/static/foo%5Cbar").status == 400); // decoded -> "foo\bar"
  // Missing -> 404.
  REQUIRE(rawRequest(fx.port, "GET", "/static/nope.css").status == 404);
  // Benign -> 200.
  REQUIRE(rawRequest(fx.port, "GET", "/static/app.css").status == 200);
}

TEST_CASE("wsChannel() returns a stable reference (findOrInsert)", "[application][channels][ws]")
{
  AppFixture fx;
  iora::web::WsChannel &w1 = fx.app.wsChannel("wsroom");
  iora::web::WsChannel &w2 = fx.app.wsChannel("wsroom");
  REQUIRE(&w1 == &w2); // same object
  REQUIRE(w1.name() == "wsroom");
  REQUIRE(&fx.app.wsChannel("other") != &w1); // distinct name -> distinct object
}

// ===========================================================================
// task-8.5.3 — RD-20 / N-1 concurrent reload (filesystem mode, ASAN/TSAN)
// ===========================================================================

TEST_CASE("serveStatic + render survive concurrent reload() in filesystem mode (RD-20/N-1)",
          "[application][reload][lifetime]")
{
  TempTree tree("reload");
  tree.writeStatic("app.css", "body{color:blue}");
  tree.writeTemplate("page.html", "<h1>{{title}}</h1>");

  Assets assets = Assets::fromDirectory(tree.root);
  core::TimerService timer;
  timer.start();
  HttpServer srv;
  int port = nextPort();
  srv.setPort(port);
  Application app(srv, assets, timer);
  app.page("/fs", "page.html",
           [](const Request &, Response &, parsers::Json &data)
           { data["title"] = parsers::Json("Live"); });
  app.serveStatic("/static/");
  srv.start();
  std::this_thread::sleep_for(300ms);

  // Reloader MUTATES the files (varying length) each iteration so every reload()
  // reallocates the cache/template buffers — a held string_view into the old
  // buffer would dangle (the N-1/RD-20 hazard) and surface under ASAN/TSAN. The
  // stable PREFIXES below let the readers assert byte correctness (no torn read).
  std::atomic<bool> stop{false};
  std::thread reloader(
    [&]()
    {
      int i = 0;
      while (!stop.load())
      {
        std::string pad((i++ % 7), 'x');
        tree.writeStatic("app.css", "body{color:blue}/*" + pad + "*/");
        tree.writeTemplate("page.html", "<h1>{{title}}</h1><!--" + pad + "-->");
        assets.reload();
        std::this_thread::sleep_for(1ms);
      }
    });

  std::atomic<int> ok{0};
  std::vector<std::thread> workers;
  for (int t = 0; t < 4; ++t)
  {
    workers.emplace_back(
      [&]()
      {
        for (int i = 0; i < 40; ++i)
        {
          RawResponse a = rawRequest(port, "GET", "/fs");
          RawResponse b = rawRequest(port, "GET", "/static/app.css");
          // Byte-correctness (L-1): the rendered page always contains the stable
          // interpolation; the css always begins with the stable prefix — proves
          // a complete (not torn / not freed) representation was served.
          if (a.status == 200 && a.body.find("<h1>Live</h1>") != std::string::npos &&
              b.status == 200 && b.body.rfind("body{color:blue}", 0) == 0)
          {
            ok.fetch_add(1);
          }
        }
      });
  }
  for (auto &w : workers)
  {
    w.join();
  }
  stop.store(true);
  reloader.join();

  REQUIRE(ok.load() == 4 * 40); // every request well-formed + correct, no UAF under ASAN/TSAN

  app.shutdown();
  srv.stop();
  timer.stop();
}

// ===========================================================================
// task-8.5.4 — SSE subscribe/publish, heartbeat, graceful shutdown, channels
// ===========================================================================

TEST_CASE("SSE subscribe + publish fan-out end-to-end (RD-3)", "[application][sse]")
{
  AppFixture fx;
  SseChannel &chan = fx.app.sseChannel("updates");
  fx.app.subscribeRoute("/events", chan);
  fx.start();

  Conn c;
  REQUIRE(c.open(fx.port));
  c.sendRequest("GET", "/events", "Accept: text/event-stream\r\n", "", true);
  std::string preamble = c.readUntil("\r\n\r\n");
  REQUIRE(preamble.rfind("HTTP/1.1 200 OK\r\n", 0) == 0);
  REQUIRE(preamble.find("text/event-stream") != std::string::npos);

  REQUIRE(waitFor([&]() { return chan.subscriberCount() == 1; }));
  chan.publish("update", "<tr>x</tr>");
  std::string got = c.readUntil("event: update\ndata: <tr>x</tr>\n\n");
  REQUIRE(got.find("event: update\ndata: <tr>x</tr>\n\n") != std::string::npos);
}

TEST_CASE("SSE heartbeat keeps an idle subscriber alive (proves SseManager::add)",
          "[application][sse][heartbeat]")
{
  AppFixture fx(100ms); // short heartbeat
  SseChannel &chan = fx.app.sseChannel("hb");
  fx.app.subscribeRoute("/hb", chan);
  fx.start();

  Conn c;
  REQUIRE(c.open(fx.port));
  c.sendRequest("GET", "/hb", "Accept: text/event-stream\r\n", "", true);
  c.readUntil("\r\n\r\n");
  std::string got = c.readUntil(": keepalive\n\n", 3000);
  REQUIRE(got.find(": keepalive\n\n") != std::string::npos);
}

TEST_CASE("SSE graceful shutdown emits ':shutting down' with no later keepalive",
          "[application][sse][shutdown]")
{
  AppFixture fx(100ms);
  SseChannel &chan = fx.app.sseChannel("down");
  fx.app.subscribeRoute("/down", chan);
  fx.start();

  Conn c;
  REQUIRE(c.open(fx.port));
  c.sendRequest("GET", "/down", "Accept: text/event-stream\r\n", "", true);
  c.readUntil("\r\n\r\n");
  c.readUntil(": keepalive\n\n", 2000); // ensure at least one keepalive flowed

  fx.app.shutdown(); // graceful SSE drain before transport teardown
  std::string got = c.readUntil(": shutting down\n\n", 2000);
  std::size_t marker = got.find(": shutting down\n\n");
  REQUIRE(marker != std::string::npos);
  // No keepalive AFTER the shutting-down marker (draining handshake).
  REQUIRE(got.find(": keepalive\n\n", marker + 1) == std::string::npos);
}

TEST_CASE("sseChannel() returns a stable reference; publish before subscriber is a no-op",
          "[application][channels]")
{
  AppFixture fx;
  SseChannel &a1 = fx.app.sseChannel("room");
  SseChannel &a2 = fx.app.sseChannel("room");
  REQUIRE(&a1 == &a2); // same object (findOrInsert)
  REQUIRE(fx.app.sseChannel("room").subscriberCount() == 0);
  a1.publish("x", "y"); // zero-subscriber publish: no-op, no crash
  REQUIRE(a1.subscriberCount() == 0);
}

// ===========================================================================
// task-8.5.4 — metrics. The disabled-by-default case MUST precede the enabled
// case (Catch2 runs in declaration order; MetricsRegistry is a process
// singleton with no reset).
// ===========================================================================

TEST_CASE("metrics disabled by default: /metrics 404 and no web_* series", "[application][metrics][off]")
{
  AppFixture fx;
  fx.app.page("/p", "page.html",
              [](const Request &, Response &, parsers::Json &d) { d["title"] = parsers::Json("p"); });
  fx.start();
  REQUIRE(rawRequest(fx.port, "GET", "/p").status == 200);
  REQUIRE(rawRequest(fx.port, "GET", "/metrics").status == 404);
  REQUIRE(core::MetricsRegistry::instance().snapshotJson().find("web_") == std::string::npos);
}

TEST_CASE("enableMetrics: /metrics serves Prometheus; {route} is the pattern; SSE gauge",
          "[application][metrics][on]")
{
  AppFixture fx;
  fx.app.enableMetrics(); // BEFORE route/channel registration (gauge resolved at registration)
  fx.app.page("/users/:id", "page.html",
              [](const Request &, Response &, parsers::Json &d) { d["title"] = parsers::Json("u"); });
  SseChannel &chan = fx.app.sseChannel("metricschan");
  fx.app.subscribeRoute("/metricsevents", chan);
  fx.start();

  REQUIRE(rawRequest(fx.port, "GET", "/users/42").status == 200);
  RawResponse m = rawRequest(fx.port, "GET", "/metrics");
  REQUIRE(m.status == 200);
  REQUIRE(m.header("content-type") == "text/plain; version=0.0.4; charset=utf-8");
  REQUIRE(m.body.find("web_request_duration_seconds") != std::string::npos);
  REQUIRE(m.body.find("web_responses_total") != std::string::npos);
  // RD-25: route label is the PATTERN, not the concrete path.
  REQUIRE(m.body.find("/users/:id") != std::string::npos);
  REQUIRE(m.body.find("/users/42") == std::string::npos);

  // SSE gauge: subscribe -> 1, close -> 0.
  {
    Conn c;
    REQUIRE(c.open(fx.port));
    c.sendRequest("GET", "/metricsevents", "Accept: text/event-stream\r\n", "", true);
    c.readUntil("\r\n\r\n");
    REQUIRE(waitFor([&]() { return chan.subscriberCount() == 1; }));
    RawResponse g1 = rawRequest(fx.port, "GET", "/metrics");
    auto v1 = prometheusValue(g1.body, "web_sse_subscribers");
    REQUIRE(v1.has_value());
    REQUIRE(*v1 == Approx(1.0));
    c.closeFd(); // disconnect -> onClose decrement
  }
  REQUIRE(waitFor(
    [&]()
    {
      RawResponse g = rawRequest(fx.port, "GET", "/metrics");
      auto v = prometheusValue(g.body, "web_sse_subscribers");
      return v.has_value() && *v == Approx(0.0);
    },
    5000));
}

// ===========================================================================
// task-8.5.5 — lifecycle (APP-7), single-Application (APP-8), cpp17-L4
// ===========================================================================

TEST_CASE("APP-7: in-flight handler reading Assets drains before http.stop() returns",
          "[application][lifecycle]")
{
  AppFixture fx;
  std::atomic<bool> inHandler{false};
  std::atomic<bool> handlerDone{false};
  fx.app.page("/slow", "page.html",
              [&](const Request &, Response &, parsers::Json &data)
              {
                inHandler.store(true);
                std::this_thread::sleep_for(400ms); // simulate work holding the handler
                data["title"] = parsers::Json("slow");
                handlerDone.store(true);
              });
  fx.start();

  std::thread requester([&]() { rawRequest(fx.port, "GET", "/slow"); });
  REQUIRE(waitFor([&]() { return inHandler.load(); }, 3000));
  // stop() must block until the in-flight handler finishes draining.
  fx.srv.stop();
  REQUIRE(handlerDone.load()); // handler completed before stop() returned
  requester.join();
}

TEST_CASE("APP-8: single Application per HttpServer serves correctly", "[application][single]")
{
  AppFixture fx;
  fx.app.page("/only", "page.html",
              [](const Request &, Response &, parsers::Json &d) { d["title"] = parsers::Json("one"); });
  fx.start();
  REQUIRE(rawRequest(fx.port, "GET", "/only").status == 200);
}

TEST_CASE("cpp17-L4: concurrent sseChannel(name) returns one shared object (TSAN)",
          "[application][channels][concurrency]")
{
  AppFixture fx;
  constexpr int kThreads = 8;
  std::vector<std::thread> threads;
  std::array<SseChannel *, kThreads> ptrs{};
  for (int i = 0; i < kThreads; ++i)
  {
    threads.emplace_back([&, i]() { ptrs[i] = &fx.app.sseChannel("shared"); });
  }
  for (auto &t : threads)
  {
    t.join();
  }
  for (int i = 1; i < kThreads; ++i)
  {
    REQUIRE(ptrs[i] == ptrs[0]); // factory ran once; all observe the same object
  }
}

TEST_CASE("SSE subscriber gauge nets to 0 under concurrent connect/disconnect (RD-22, TSAN)",
          "[application][sse][metrics][concurrency]")
{
  AppFixture fx(100ms); // short heartbeat: ticks race the connect/disconnect churn
  fx.app.enableMetrics();
  SseChannel &chan = fx.app.sseChannel("churn");
  fx.app.subscribeRoute("/churn", chan);
  fx.start();

  constexpr int kConns = 12;
  std::vector<std::unique_ptr<Conn>> conns;
  std::vector<std::thread> openers;
  std::mutex mtx;
  for (int i = 0; i < kConns; ++i)
  {
    openers.emplace_back(
      [&]()
      {
        auto c = std::make_unique<Conn>();
        if (c->open(fx.port))
        {
          c->sendRequest("GET", "/churn", "Accept: text/event-stream\r\n", "", true);
          c->readUntil("\r\n\r\n");
          std::lock_guard<std::mutex> lk(mtx);
          conns.push_back(std::move(c));
        }
      });
  }
  for (auto &t : openers)
  {
    t.join();
  }
  REQUIRE(waitFor([&]() { return chan.subscriberCount() == kConns; }));

  // Close all concurrently while heartbeat ticks run.
  std::vector<std::thread> closers;
  for (auto &c : conns)
  {
    closers.emplace_back([&c]() { c->closeFd(); });
  }
  for (auto &t : closers)
  {
    t.join();
  }

  // Gauge nets back to exactly 0 via the per-stream onClose decrement.
  REQUIRE(waitFor(
    [&]()
    {
      RawResponse g = rawRequest(fx.port, "GET", "/metrics");
      auto v = prometheusValue(g.body, "web_sse_subscribers");
      return v.has_value() && *v == Approx(0.0);
    },
    8000));
}
