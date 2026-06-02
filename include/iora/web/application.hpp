// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// iora HTMX support — Phase 8: the consumer-facing Application wiring facade.
// Architecture: coding_trackers/architecture/iora/application_wiring.json (R4).
//
// Application is a thin coordinator over the tier-0/1/2 primitives (extended
// HttpServer routing, Mustache, Assets, SSE/WS channels + SseManager, htmx
// helpers). It owns NO thread of its own (APP-1): it rides an INJECTED
// core::TimerService for the SSE heartbeat and registers std::function handlers
// against HttpServer during the setup window (before http.start()).

#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <iora/core/concurrent_hash_map.hpp>
#include <iora/core/logger.hpp>
#include <iora/core/metrics.hpp>
#include <iora/core/timer.hpp>
#include <iora/network/http_server.hpp>
#include <iora/network/sse_stream.hpp>
#include <iora/parsers/html_escape.hpp>
#include <iora/parsers/json.hpp>
#include <iora/parsers/mustache.hpp>
#include <iora/web/assets.hpp>
#include <iora/web/channel.hpp>
#include <iora/web/htmx.hpp>

namespace iora
{
namespace web
{

/// \brief Top-level consumer-facing facade wiring the HTMX primitives into the
/// Hello-Admin developer experience. Single Application per HttpServer (APP-8).
///
/// Non-copyable AND non-movable: it owns a network::SseManager by value (copy
/// deleted, move implicitly deleted), a core::ConcurrentHashMap registry
/// (copy/move deleted), and reference members. Construct it in place.
///
/// Lifetime (APP-7 / RD-26): the Assets& AND the core::TimerService& passed to
/// the constructor MUST outlive this Application and the in-flight-handler
/// drain. Safe teardown: app.shutdown() -> http.stop() -> timer.stop() ->
/// destroy Application -> destroy Assets/TimerService/HttpServer.
class Application
{
public:
  /// \brief Build the render context for a page/fragment GET handler. Receives
  /// the request (query params, htmx::isHtmx, ...), the response (may set
  /// status/headers), and a mutable Json& to populate.
  using DataBuilder = std::function<void(const network::HttpServer::Request &,
                                         network::HttpServer::Response &, parsers::Json &)>;

  /// \brief Handle a postFragment POST. Receives the already-parsed form map,
  /// the response (may set status), and a mutable Json& for the rendered fragment.
  using FormHandler =
    std::function<void(const std::unordered_map<std::string, std::string> &form,
                       network::HttpServer::Response &, parsers::Json &)>;

  /// \brief Construct over an HttpServer, an Assets, and an injected, STARTED
  /// core::TimerService. heartbeatInterval is defaulted (15s) and threaded into
  /// the internal SseManager so tests can shorten the SSE heartbeat (M-1).
  Application(network::HttpServer &http, Assets &assets, core::TimerService &timer,
              std::chrono::milliseconds heartbeatInterval = std::chrono::milliseconds(15000))
      : _http(http), _assets(assets), _timer(timer), _sseManager(http, timer, heartbeatInterval)
  {
  }

  ~Application()
  {
    // Idempotent backstop: ensure the SSE manager has drained before the
    // channel registry / transport go away (shutdownOrdering step 5).
    _sseManager.shutdown();
  }

  Application(const Application &) = delete;
  Application &operator=(const Application &) = delete;
  Application(Application &&) = delete;
  Application &operator=(Application &&) = delete;

  // ── render (RD-14 / OQ-11) ────────────────────────────────────────────────

  /// \brief Resolve + render a template; MAY THROW, sets no HTTP status.
  /// page/fragment/postFragment are the catch points (RD-14/APP-9).
  std::string render(std::string_view templateName, const parsers::Json &data) const
  {
    std::optional<std::string_view> tmplView = _assets.getTemplate(templateName);
    if (!tmplView)
    {
      core::Logger::error("Application::render: template not found: " +
                          std::string(templateName));
      throw parsers::MustacheError("template not found: " + std::string(templateName));
    }
    // N-1: the filesystem-mode getTemplate view is NOT reload-safe — copy the
    // top-level template into an owning std::string BEFORE the render (reload
    // boundary). Only getStatic's StaticBlob is reload-safe (RD-20).
    std::string tmpl(*tmplView);
    parsers::PartialResolver resolver =
      [this](std::string_view name) -> std::optional<std::string>
    {
      std::optional<std::string_view> t = _assets.getTemplate(name);
      if (!t)
      {
        return std::nullopt;
      }
      return std::string(*t); // owning copy per partial (no reload-boundary view)
    };
    return parsers::Mustache::render(tmpl, data, resolver);
  }

  // ── page / fragment / postFragment ────────────────────────────────────────

  /// \brief Register a GET route rendering a FULL HTML document (RD-14 catch).
  void page(std::string_view path, std::string_view templateName, DataBuilder build)
  {
    std::string route(path);
    std::string tmpl(templateName);
    auto coreFn = [this, tmpl, build = std::move(build)](
                    const network::HttpServer::Request &req,
                    network::HttpServer::Response &res)
    {
      parsers::Json data;
      build(req, res, data);
      try
      {
        res.set_content(render(tmpl, data), "text/html; charset=utf-8");
      }
      catch (const std::exception &e)
      {
        setErrorBody(res, e, tmpl);
      }
    };
    _http.onGet(route, instrument(route, std::move(coreFn)));
  }

  /// \brief Register a GET route rendering a BARE HTML fragment (HTMX target).
  void fragment(std::string_view path, std::string_view templateName, DataBuilder build)
  {
    std::string route(path);
    std::string tmpl(templateName);
    auto coreFn = [this, tmpl, build = std::move(build)](
                    const network::HttpServer::Request &req,
                    network::HttpServer::Response &res)
    {
      parsers::Json data;
      build(req, res, data);
      try
      {
        res.set_content(render(tmpl, data), "text/html; charset=utf-8");
      }
      catch (const std::exception &e)
      {
        setErrorBody(res, e, tmpl);
      }
    };
    _http.onGet(route, instrument(route, std::move(coreFn)));
  }

  /// \brief Register a POST route: parse the urlencoded body, run the handler,
  /// render the fragment. A render failure -> 500 OVERRIDES a FormHandler status.
  void postFragment(std::string_view path, std::string_view templateName, FormHandler handle)
  {
    std::string route(path);
    std::string tmpl(templateName);
    auto coreFn = [this, tmpl, handle = std::move(handle)](
                    const network::HttpServer::Request &req,
                    network::HttpServer::Response &res)
    {
      std::unordered_map<std::string, std::string> form = parsers::parseFormBody(req.body);
      parsers::Json data;
      handle(form, res, data);
      try
      {
        res.set_content(render(tmpl, data), "text/html; charset=utf-8");
      }
      catch (const std::exception &e)
      {
        setErrorBody(res, e, tmpl); // render failure overrides any FormHandler status
      }
    };
    _http.onPost(route, instrument(route, std::move(coreFn)));
  }

  // ── serveStatic (RD-4 / RD-10 / RD-20 / RD-21) ────────────────────────────

  /// \brief Register a trailing-wildcard GET route serving static assets, owning
  /// all static-response header policy (RD-4): select-then-compare conditional
  /// requests, per-representation ETag, gzip negotiation, security headers.
  void serveStatic(std::string_view prefix)
  {
    std::string route = std::string(prefix) + "*";
    auto coreFn = [this](const network::HttpServer::Request &req,
                         network::HttpServer::Response &res)
    {
      // pathRest is RAW (http_server.hpp:1775); getStatic never decodes (M-c).
      // Decode EXACTLY ONCE; run the pre-check AND getStatic on the decoded path.
      std::string decodedPath = parsers::urlDecode(req.pathRest);

      // OQ-9 cheap pre-check on the DECODED form (catches %2e%2e).
      if (hasDotDotSegment(decodedPath) || (!decodedPath.empty() && decodedPath.front() == '/'))
      {
        core::Logger::warning("serveStatic: rejected adversarial path: " + decodedPath);
        res.status = 400;
        res.set_content("Bad request", "text/plain; charset=utf-8");
        return;
      }

      GetStaticResult result = _assets.getStatic(decodedPath);
      if (result.status == GetStaticResult::Status::Rejected)
      {
        core::Logger::warning("serveStatic: getStatic rejected path: " + decodedPath);
        res.status = 400;
        res.set_content("Bad request", "text/plain; charset=utf-8");
        return;
      }
      if (result.status == GetStaticResult::Status::NotFound)
      {
        core::Logger::debug("serveStatic: not found: " + decodedPath);
        res.status = 404;
        res.set_content("Not Found", "text/plain; charset=utf-8");
        return;
      }

      const StaticBlob &blob = result.blob;

      // Step 4: SELECT representation FIRST (web M-1 / web L-1).
      // Identity is always an acceptable fallback: a client that sends
      // "identity;q=0" still receives the identity bytes (we never emit 406).
      // The blob.gzipBytes.has_value() conjunct hardens the later *blob.gzipBytes
      // deref against any future drift in the gzipVariantExists<->gzipBytes
      // Assets invariant (web L-1).
      const bool serveGzip = blob.gzipVariantExists && blob.gzipBytes.has_value() &&
                             gzipAcceptable(req.get_header_value("Accept-Encoding"));
      const std::string_view selectedEtagRaw = serveGzip ? blob.gzipEtag : blob.rawEtag;
      const std::string selectedQuoted = "\"" + std::string(selectedEtagRaw) + "\"";
      const std::string cacheControl =
        _devMode.load(std::memory_order_relaxed) ? "no-store" : "public, max-age=3600";

      // Step 5: If-None-Match against the SELECTED representation (weak compare).
      const std::string inm = req.get_header_value("If-None-Match");
      if (!inm.empty() && ifNoneMatchMatches(inm, selectedQuoted))
      {
        // Step (304): RD-21/APP-10 — DIRECT field writes, never set_content.
        // Strip any body-framing headers the dispatcher pre-seeded on res (the
        // default response carries Content-Type/Content-Length) so the bodyless
        // 304 drags NO stale Content-Length or Content-Type along. Omitting
        // Content-Length is also the RFC 9110 §15.4.5 / RFC 9112 §6.2 compliant
        // form (a non-empty 200 body means "0" would be wrong).
        res.status = 304;
        res.body.clear();
        res.headers.erase("Content-Length");
        res.headers.erase("Content-Type");
        res.headers.erase("Content-Encoding");
        res.set_header("ETag", selectedQuoted);
        res.set_header("Cache-Control", cacheControl);
        if (blob.gzipVariantExists)
        {
          res.set_header("Vary", "Accept-Encoding"); // AC-2: keyed off gzipVariantExists
        }
        res.set_header("X-Content-Type-Options", "nosniff"); // web H-1
        // No Content-Encoding, no body, no CSP (delivered with the 200's body).
        return;
      }

      // Step 6: 200 with the SELECTED representation.
      const std::string_view body = serveGzip ? *blob.gzipBytes : blob.bytes;
      const std::string mime(blob.mime);
      res.set_content(std::string(body), mime); // body + Content-Type + Content-Length
      res.set_header("ETag", selectedQuoted);    // per-representation (M-f)
      res.set_header("Cache-Control", cacheControl);
      if (blob.gzipVariantExists)
      {
        res.set_header("Vary", "Accept-Encoding"); // AC-2
      }
      res.set_header("X-Content-Type-Options", "nosniff"); // web H-1
      if (serveGzip)
      {
        res.set_header("Content-Encoding", "gzip");
      }
      // web H-1/L-2: SVG/HTML active-content stored-XSS mitigation (on the 200
      // only). Bare "sandbox" (no allow-* tokens) is the deliberate, strongest
      // choice: it neutralizes script/plugin/top-navigation when the asset is
      // navigated-to or framed, yet does not affect inline <img src=...svg>
      // (images never execute SVG script). v1 applies it uniformly to every
      // svg/html static asset (no per-asset opt-out — knownLimitation).
      if (startsWith(mime, "image/svg+xml") || startsWith(mime, "text/html"))
      {
        res.set_header("Content-Security-Policy", "sandbox");
      }
    };
    _http.onGet(route, instrument(route, std::move(coreFn)));
  }

  // ── channels (RD-16 / RD-27) ──────────────────────────────────────────────

  /// \brief Get-or-create a named SseChannel. Stable reference for its lifetime
  /// (shared_ptr-backed ConcurrentHashMap; findOrInsert factory runs once).
  SseChannel &sseChannel(std::string_view name)
  {
    std::string key(name);
    // FACTORY CONSTRAINT (thread L-1): allocation-only — no re-entrant registry
    // access, no user callback, no other lock (runs under the shard unique_lock).
    std::shared_ptr<SseChannel> ptr =
      _sseChannels.findOrInsert(key, [&key]() { return std::make_shared<SseChannel>(key); });
    return *ptr;
  }

  /// \brief Get-or-create a named WsChannel (return-ref-only in v1; the consumer
  /// wires WS sessions via WsChannel::subscribe(WebSocketServer&, SessionId)).
  WsChannel &wsChannel(std::string_view name)
  {
    std::string key(name);
    std::shared_ptr<WsChannel> ptr =
      _wsChannels.findOrInsert(key, [&key]() { return std::make_shared<WsChannel>(key); });
    return *ptr;
  }

  // ── subscribeRoute (RD-3 / RD-22 / RD-24) ─────────────────────────────────

  /// \brief Register a GET route that upgrades the connection to SSE and
  /// subscribes the new stream to `channel`.
  ///
  /// NOTE (metrics ordering): the per-channel SSE-subscriber gauge is resolved
  /// ONCE here at registration time. Call enableMetrics() BEFORE subscribeRoute()
  /// or the gauge is not wired for this channel (the page/fragment request
  /// metrics, by contrast, are observe-time resolved and order-independent).
  void subscribeRoute(std::string_view path, SseChannel &channel)
  {
    std::string route(path);
    SseChannel *chan = &channel;
    // RD-22 / thread-M2: resolve the {channel} gauge ONCE at registration when
    // metrics are enabled (call enableMetrics before subscribeRoute). The Gauge&
    // is registry-singleton-owned, stable for process lifetime.
    core::Gauge *gauge = nullptr;
    if (_metricsEnabled.load(std::memory_order_relaxed))
    {
      gauge = &core::MetricsRegistry::instance().gauge(
        "web_sse_subscribers", {{"channel", channel.name()}},
        "Live SSE subscribers per channel");
    }
    _http.onGet(route,
                [this, chan, gauge](const network::HttpServer::Request &req,
                                    network::HttpServer::Response &res)
                {
                  network::upgradeToSse(
                    _http, req, res,
                    [this, chan, gauge](std::shared_ptr<network::SseStream> stream)
                    {
                      // APP-11/RD-24: register with the manager FIRST (arms the
                      // 15s heartbeat lazily on the first stream).
                      _sseManager.add(stream);
                      chan->subscribe(stream);
                      if (gauge)
                      {
                        // RD-22: increment STRICTLY BEFORE registering onClose,
                        // so an already-closed stream's immediate-fire decrements.
                        // The (allocating) add()/subscribe() above are sequenced
                        // BEFORE the increment, so a throw there cannot leave the
                        // gauge incremented-without-a-decrement; onClose's slot
                        // store is a small-closure move (no allocation).
                        gauge->increment();
                        stream->onClose([gauge]() { gauge->decrement(); });
                      }
                    });
                });
  }

  // ── metrics (OQ-8 / RD-28) ────────────────────────────────────────────────

  /// \brief Enable the thin web-metrics instrumentation and the /metrics
  /// endpoint. Call BEFORE registering routes/channels (setup window). No-op
  /// metric series exist until called (zero overhead when disabled).
  void enableMetrics(std::string_view path = "/metrics")
  {
    _metricsEnabled.store(true, std::memory_order_relaxed);
    _http.onGet(std::string(path),
                [](const network::HttpServer::Request &,
                   network::HttpServer::Response &res)
                {
                  res.set_content(core::MetricsRegistry::instance().prometheusExport(),
                                  "text/plain; version=0.0.4; charset=utf-8");
                });
  }

  // ── devMode / shutdown ────────────────────────────────────────────────────

  /// \brief Toggle dev mode (verbose 500 bodies + no-store static cache).
  /// std::atomic relaxed (RD-28): no plain-bool cross-thread race.
  void setDevMode(bool dev) { _devMode.store(dev, std::memory_order_relaxed); }

  /// \brief Graceful SSE teardown. MUST be called before the HttpServer
  /// transport is torn down (before/within http.stop()). Idempotent.
  void shutdown() { _sseManager.shutdown(); }

private:
  // ── error body (OQ-5 / APP-2) ─────────────────────────────────────────────

  void setErrorBody(network::HttpServer::Response &res, const std::exception &e,
                    const std::string &templateName) const
  {
    res.status = 500;
    if (_devMode.load(std::memory_order_relaxed))
    {
      res.set_content(std::string("Internal Server Error: ") + e.what() +
                        " (template: " + templateName + ")",
                      "text/plain; charset=utf-8");
    }
    else
    {
      res.set_content("Internal Server Error", "text/plain; charset=utf-8");
    }
  }

  // ── metrics instrumentation (RD-25 / RD-28) ───────────────────────────────

  /// \brief Wrap a handler with request-duration + response-counter
  /// instrumentation, resolved per-(route,status) at observe time. `route` is
  /// the registration-time pattern, owned by value here (RD-25). No-op when
  /// metrics are disabled.
  network::HttpServer::Handler
  instrument(std::string route,
             std::function<void(const network::HttpServer::Request &,
                                network::HttpServer::Response &)>
               coreFn)
  {
    return [this, route = std::move(route), coreFn = std::move(coreFn)](
             const network::HttpServer::Request &req,
             network::HttpServer::Response &res)
    {
      if (!_metricsEnabled.load(std::memory_order_relaxed))
      {
        coreFn(req, res);
        return;
      }
      const auto start = std::chrono::steady_clock::now();
      coreFn(req, res);
      const double elapsed =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
      const std::string status = std::to_string(res.status);
      const core::Labels labels{{"route", route}, {"status", status}};
      core::MetricsRegistry::instance()
        .histogram("web_request_duration_seconds", labels, core::Histogram::DEFAULT_BUCKETS,
                   "Web request duration in seconds")
        .observe(elapsed);
      core::MetricsRegistry::instance()
        .counter("web_responses_total", labels, "Total web responses by route and status")
        .increment();
    };
  }

  // ── static helpers ─────────────────────────────────────────────────────────

  static bool startsWith(std::string_view s, std::string_view prefix)
  {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
  }

  static std::string_view trimView(std::string_view s)
  {
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && isOws(s[b]))
    {
      ++b;
    }
    while (e > b && isOws(s[e - 1]))
    {
      --e;
    }
    return s.substr(b, e - b);
  }

  static bool isOws(char c) { return c == ' ' || c == '\t'; }

  static bool asciiIEquals(std::string_view a, std::string_view b)
  {
    if (a.size() != b.size())
    {
      return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i)
    {
      const char ca = asciiLower(a[i]);
      const char cb = asciiLower(b[i]);
      if (ca != cb)
      {
        return false;
      }
    }
    return true;
  }

  static char asciiLower(char c)
  {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u >= 'A' && u <= 'Z')
    {
      return static_cast<char>(u - 'A' + 'a');
    }
    return c;
  }

  /// \brief True iff the path has a ".." path segment (split on '/').
  static bool hasDotDotSegment(std::string_view path)
  {
    std::size_t start = 0;
    while (true)
    {
      const std::size_t slash = path.find('/', start);
      const std::string_view seg =
        (slash == std::string_view::npos) ? path.substr(start) : path.substr(start, slash - start);
      if (seg == "..")
      {
        return true;
      }
      if (slash == std::string_view::npos)
      {
        break;
      }
      start = slash + 1;
    }
    return false;
  }

  /// \brief RFC 9110 §12.5.3 Accept-Encoding acceptability for gzip (q-values).
  /// gzip acceptable iff an explicit 'gzip' entry (else '*') has a non-zero
  /// qvalue; absent header / q=0 -> identity. NOT a naive contains() (web L-1).
  static bool gzipAcceptable(std::string_view ae)
  {
    if (trimView(ae).empty())
    {
      return false;
    }
    std::optional<double> gzipQ;
    std::optional<double> starQ;
    std::size_t pos = 0;
    while (pos <= ae.size())
    {
      const std::size_t comma = ae.find(',', pos);
      const std::string_view entry =
        (comma == std::string_view::npos) ? ae.substr(pos) : ae.substr(pos, comma - pos);
      pos = (comma == std::string_view::npos) ? ae.size() + 1 : comma + 1;

      const std::size_t semi = entry.find(';');
      const std::string_view coding = trimView(entry.substr(0, semi));
      double q = 1.0;
      if (semi != std::string_view::npos)
      {
        q = qValueOf(entry.substr(semi + 1));
      }
      if (asciiIEquals(coding, "gzip"))
      {
        gzipQ = q;
      }
      else if (coding == "*")
      {
        starQ = q;
      }
    }
    const double eff = gzipQ ? *gzipQ : (starQ ? *starQ : 0.0);
    return eff > 0.0;
  }

  /// \brief Parse the q-value from a ';'-separated parameter list. Absent q ->
  /// 1.0 (a coding with no q defaults to q=1, RFC 9110 §12.5.3). A present but
  /// MALFORMED / out-of-range q -> 0.0 (treated as not-acceptable, the
  /// conservative choice — a garbage q must never enable a coding).
  static double qValueOf(std::string_view params)
  {
    std::size_t pos = 0;
    while (pos <= params.size())
    {
      const std::size_t semi = params.find(';', pos);
      const std::string_view param =
        (semi == std::string_view::npos) ? params.substr(pos) : params.substr(pos, semi - pos);
      pos = (semi == std::string_view::npos) ? params.size() + 1 : semi + 1;

      const std::size_t eq = param.find('=');
      if (eq == std::string_view::npos)
      {
        continue;
      }
      const std::string_view name = trimView(param.substr(0, eq));
      if (asciiIEquals(name, "q"))
      {
        return parseQValue(trimView(param.substr(eq + 1)));
      }
    }
    return 1.0; // no explicit q -> q=1
  }

  /// \brief Locale-INDEPENDENT RFC 9110 §12.5.3 qvalue parse: ( "0" [ "."
  /// 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] ). Returns the value in [0,1], or
  /// 0.0 for any malformed / out-of-range input (NOT std::stod, which is
  /// locale-sensitive and accepts scientific/out-of-range forms).
  static double parseQValue(std::string_view v)
  {
    if (v.empty())
    {
      return 0.0;
    }
    double whole;
    if (v[0] == '0')
    {
      whole = 0.0;
    }
    else if (v[0] == '1')
    {
      whole = 1.0;
    }
    else
    {
      return 0.0; // invalid leading digit
    }
    double frac = 0.0;
    double scale = 0.1;
    std::size_t i = 1;
    if (i < v.size())
    {
      if (v[i] != '.')
      {
        return 0.0; // junk after the leading digit
      }
      ++i;
      int digits = 0;
      for (; i < v.size(); ++i, ++digits)
      {
        const char c = v[i];
        if (c < '0' || c > '9' || digits >= 3)
        {
          return 0.0; // non-digit or >3 fractional digits (grammar violation)
        }
        frac += static_cast<double>(c - '0') * scale;
        scale *= 0.1;
      }
    }
    const double q = whole + frac;
    if (q > 1.0)
    {
      return 0.0; // out of range (e.g. "1.5") is invalid -> not acceptable
    }
    return q;
  }

  /// \brief If-None-Match evaluation (RFC 9110 §13.1.2 weak comparison) against
  /// the selected representation's quoted ETag. Returns true -> emit 304.
  static bool ifNoneMatchMatches(std::string_view inm, const std::string &selectedQuoted)
  {
    std::size_t pos = 0;
    while (pos <= inm.size())
    {
      const std::size_t comma = inm.find(',', pos);
      std::string_view entry =
        (comma == std::string_view::npos) ? inm.substr(pos) : inm.substr(pos, comma - pos);
      pos = (comma == std::string_view::npos) ? inm.size() + 1 : comma + 1;
      entry = trimView(entry);
      if (entry == "*")
      {
        return true;
      }
      // Weak comparison: strip a leading W/ before comparing opaque-tag bodies
      // (the selected ETag is strong / unprefixed).
      if (entry.size() >= 2 && entry[0] == 'W' && entry[1] == '/')
      {
        entry.remove_prefix(2);
      }
      if (entry == selectedQuoted)
      {
        return true;
      }
    }
    return false;
  }

  network::HttpServer &_http;
  Assets &_assets;
  core::TimerService &_timer;
  std::atomic<bool> _devMode{false};
  network::SseManager _sseManager; // constructed (_http,_timer,heartbeatInterval)
  std::atomic<bool> _metricsEnabled{false};
  core::ConcurrentHashMap<std::string, std::shared_ptr<SseChannel>> _sseChannels;
  core::ConcurrentHashMap<std::string, std::shared_ptr<WsChannel>> _wsChannels;
};

} // namespace web
} // namespace iora
