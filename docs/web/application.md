# Iora Web Application Wiring — Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-22 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/web/application.hpp` (header-only) |
| **Namespace** | `iora::web` |
| **Dependencies** | `iora/core/concurrent_hash_map.hpp`, `iora/core/logger.hpp`, `iora/core/metrics.hpp`, `iora/core/timer.hpp`, `iora/network/http_server.hpp`, `iora/network/sse_stream.hpp` (`SseManager`/`SseStream`/`upgradeToSse`), `iora/parsers/accept_encoding.hpp`, `iora/parsers/html_escape.hpp`, `iora/parsers/json.hpp`, `iora/parsers/mustache.hpp`, `iora/web/assets.hpp`, `iora/web/channel.hpp`, `iora/web/htmx.hpp` |
| **Tests** | `tests/web/test_application_integration.cpp` (29 `TEST_CASE`s) |
| **Architecture** | `architecture/iora/application_wiring.json` (REVISION_R4) |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-22 | Guide migrated into the grouped `docs/web/` set with a full step-13 re-verify against the current `application.hpp`. Documents `render`/`page`/`fragment`/`postFragment`, `serveStatic` (select-then-compare conditional requests, q-value `Accept-Encoding`, per-representation ETag, RD-21 304, `nosniff` + CSP for SVG/HTML), `sseChannel`/`wsChannel` (`ConcurrentHashMap` registry), `subscribeRoute` (`SseManager` wiring + RD-22 gauge), `enableMetrics`, `setDevMode`, `shutdown`; the injected-`TimerService` `SseManager`. |

---

## 1. Executive Summary

### Problem

Even with every HTMX primitive in place — pattern routing, [Mustache](../parsers/mustache.md), the [asset pipeline](asset_pipeline.md), [SSE/WS channels](../network/sse_and_channels.md) plus `SseManager`, the [`htmx::` helpers](htmx.md), Basic auth — a consumer who wires them by hand must, correctly and repeatedly:

- resolve a template through `Assets`, then build the Mustache `PartialResolver` lambda without forming a `parsers/`→`web/` include cycle;
- catch `MustacheError`/template-not-found and map each to the right dev-vs-prod 500;
- set the correct `Content-Type` for full pages vs bare fragments;
- parse the `x-www-form-urlencoded` POST body;
- register a wildcard route *and* remember to path-traversal-check and percent-decode it exactly once;
- own named channels with stable lifetimes;
- register the SSE subscribe route that calls `upgradeToSse`, suppresses the terminal response, *and* registers the stream with the `SseManager` so it receives heartbeats;
- for static assets, implement the entire RFC 9110 conditional-request / content-negotiation / security-header dance (select-then-compare ETag, q-value `Accept-Encoding`, `Vary`, `X-Content-Type-Options`, CSP for SVG, the body-less 304).

Each is a place to get it subtly wrong: a cycle, an XSS hole, a leaked stack trace in production, a dangling channel reference, a path-traversal bypass, an idle SSE connection silently reaped, a non-compliant 304.

### Solution

`iora::web::Application` is a thin coordinator that makes the correct wiring the default and collapses setup to a compact "Hello-Admin" program. It:

- owns **no thread of its own** — it rides an injected `core::TimerService` for the SSE heartbeat (APP-1);
- adds **no new subsystem** — it registers `std::function` handlers against one `HttpServer` during a setup window before `http.start()`;
- is the single place that injects the `Assets`-backed `PartialResolver`, owns the named-channel registry, owns and drives the `SseManager`, and applies production-safe error/cache behavior by default;
- optionally wires thin web metrics by reusing `core::MetricsRegistry` (no new metric subsystem).

### Technical Impact

A daemon gains a server-rendered HTMX admin UI with no SPA, no npm, and no hand-rolled HTTP-correctness or security code. The facade is opt-in and additive: a process that never constructs an `Application` is unaffected. `Application` holds no lock of its own and invokes no user callback while any lock is held.

---

## 2. System Architecture

### Component relationships

```
                 +---------------------------------------------+
   consumer ---> |  iora::web::Application  (this component)    |
   (main thread, |  page/fragment/postFragment/serveStatic/...  |
    setup window)|  -- coordinator only, owns no thread --      |
                 +---+-------+--------+---------+-----------+----+
                     |       |        |         |           |
        registers    |       | render | static  | SSE       | reuses
        handlers     v       v        v         v           v
        +--------------+ +----------+ +--------+ +---------+ +-----------------+
        | HttpServer   | | Mustache | | Assets | | Sse*    | | MetricsRegistry |
        | (worker pool)| | (parsers)| |        | | Manager | | (core, singleton)
        +--------------+ +----------+ +--------+ | /Channel| +-----------------+
                                                 +----+----+
                                        rides <-------+
                                core::TimerService (injected by consumer)
```

`Application` is a **facade**. It introduces no dispatch changes to `HttpServer`: it only registers handler closures (which run later on `HttpServer` worker threads, with no server lock held across the handler) and reads `MetricsRegistry`. It owns a `network::SseManager` by value and two `core::ConcurrentHashMap` channel registries; everything else it touches by reference.

### Threading model

| Thread | Responsibility |
|---|---|
| main thread, **setup window** (before `http.start()`) | `page`/`fragment`/`postFragment`/`serveStatic`/`sseChannel`/`wsChannel`/`subscribeRoute`/`enableMetrics`/`setDevMode` — register handlers / create channels |
| `HttpServer` worker threads | run registered handler bodies per request; no server lock held across them |
| the **injected** `core::TimerService` thread | SSE heartbeat; `SseManager` owns no thread and arms the schedule lazily on the first `add()` |
| transport engine thread | fires `SseStream` disconnect observers (lock-free dispatch) |
| any thread | channel publishers (`channel.publish`) — snapshot-then-write fan-out, no lock held during the write |

### Data flow — a page request

```mermaid
sequenceDiagram
    participant C as Client
    participant W as HttpServer worker
    participant A as Application
    participant AS as Assets
    participant M as Mustache
    C->>W: GET /dashboard
    W->>A: instrument wrapper -> page handler
    A->>A: Json data; build(req,res,data)
    A->>AS: getTemplate("dashboard.html")
    AS-->>A: string_view (copied to owning std::string, N-1)
    A->>M: render(tmpl, data, PartialResolver)
    M-->>A: HTML string
    A->>W: res.set_content(html, "text/html; charset=utf-8")
    W-->>C: 200 (instrument observes duration + responses_total)
```

---

## 3. Component Deep Dive

### Construction and ownership

```cpp
Application(network::HttpServer& http,
            Assets& assets,
            core::TimerService& timer,
            std::chrono::milliseconds heartbeatInterval = std::chrono::milliseconds(15000));
```

The constructor stores the three references and constructs an internal `network::SseManager _sseManager(http, timer, heartbeatInterval)`. The `TimerService` is **injected by the consumer**: `IoraService` exposes no timer accessor, and APP-1 forbids `Application` from owning a thread, so the heartbeat clock must be the consumer's. The trailing `heartbeatInterval` defaults to 15 s; tests shorten it (M-1).

`Application` is **non-copyable and non-movable**: it owns `SseManager` by value (copy deleted, move implicitly deleted), plus a `ConcurrentHashMap` registry (copy/move deleted) and reference members. Construct it in place; do not store it in a value container.

**Lifetime contract (APP-7 / RD-26).** The `Assets&` and `core::TimerService&` MUST outlive the `Application` **and** the in-flight-handler drain. Handlers capture `_assets` and call `getTemplate`/`getStatic` at request time, and the `SseManager` heartbeat callback promotes a `weak_ptr` per tick, so the safe teardown is:

```
app.shutdown() -> http.stop() (drains in-flight handlers) -> timer.stop()
  -> destroy Application -> destroy Assets / TimerService / HttpServer
```

### `render` — the single Mustache boundary (RD-14 / OQ-11)

```cpp
std::string render(std::string_view templateName, const parsers::Json& data) const;
```

`render` is the **only** place the `Assets`-backed `PartialResolver` is injected and the only place `Assets` meets `Mustache`. This keeps `parsers/mustache.hpp` free of any `web/` include — the only dependency edge is `web/application.hpp` → `parsers/mustache.hpp` (forward). `render` **may throw** (template-not-found from `Assets`, or `MustacheError` for a structural error / unknown partial / recursion depth) and **sets no HTTP status** — it has no `Response&`. Its callers are the catch points.

**Reload safety (N-1).** `Assets::getTemplate` returns an **owning** `std::optional<std::string>` — in filesystem mode the copy is taken under the template-cache mutex (see [asset_pipeline.md](asset_pipeline.md)), so both the top-level template and each partial resolved through the `PartialResolver` survive a concurrent `reload()`. `render` therefore carries no reload-boundary obligation; the owning return closes the same use-after-free class that `getStatic`'s `StaticBlob` closes via shared ownership.

### `page` / `fragment` / `postFragment` — render error model (RD-14 / APP-9)

All three register a handler that builds an empty `parsers::Json`, runs the consumer callback to populate it, then renders inside a **try/catch** — these are the catch points (they hold the `Response&`). On a thrown `MustacheError`/template-not-found they map to a 500 with the dev/prod body (see `setErrorBody`, OQ-5). They differ only in output shape and method:

| Method | HTTP | Body | Content-Type |
|---|---|---|---|
| `page` | GET | full HTML document | `text/html; charset=utf-8` |
| `fragment` | GET | bare HTML fragment (HTMX target) | `text/html; charset=utf-8` |
| `postFragment` | POST | bare fragment; `req.body` parsed via `parsers::parseFormBody` into the `FormHandler`'s `form` map before render | `text/html; charset=utf-8` |

For `postFragment`, the `FormHandler` may set `res.status` (e.g. 400 on a validation error); a **successful** render preserves it (HTMX swaps the fragment regardless of 2xx/4xx), but a **render failure** overrides it with the 500 (a render failure is a server error).

**`std::string` capture (RD-25).** Each method captures its `path` and `templateName` arguments **by value as `std::string`** into the registered closure — never as `std::string_view`, which would dangle past the setup call (a string-literal temporary's view is gone by request time).

### `serveStatic` — static-response header ownership (RD-4)

```cpp
void serveStatic(std::string_view prefix);   // registers a "<prefix>*" wildcard GET
```

`serveStatic` owns **all** static-response header policy; `Assets::getStatic` supplies only bytes + MIME + raw (unquoted) identity/gzip ETags + a gzip-availability flag (see [asset_pipeline.md](asset_pipeline.md)). The request pipeline:

1. **Decode once.** `req.pathRest` is captured **raw** (not percent-decoded) by the router; `Assets::getStatic` never decodes. So `serveStatic` percent-decodes `pathRest` exactly once (`parsers::urlDecode`, which is *not* plus-as-space — correct for path context) and runs both the pre-check and `getStatic` on the decoded path. No double-decode.
2. **OQ-9 pre-check** on the decoded path: a `..` segment or a leading `/` → 400, no filesystem call (logged WARN). Running on the *decoded* form is what catches `%2e%2e`.
3. **Tri-state map** of `GetStaticResult`: `Rejected` → 400 (the canonical/symlink/NUL/backslash backstop no path bypasses), `NotFound` → 404, `Found` → continue.
4. **Select representation first (web M-1 / web L-1).** `serveGzip = gzipVariantExists && gzipBytes.has_value() && gzipAcceptable(Accept-Encoding)`; `selectedEtag = serveGzip ? gzipEtag : rawEtag`. `gzipAcceptable` honors RFC 9110 §12.5.3 q-values (not a naive `contains`): a `gzip`/`*` entry with non-zero qvalue (bare token = q=1); `gzip;q=0`, `*;q=0`, or an absent header → identity. The `gzipBytes.has_value()` conjunct hardens the later `*blob.gzipBytes` deref against any future drift in the `gzipVariantExists`↔`gzipBytes` invariant.
5. **Emit headers:** quoted strong `ETag: "<selectedEtag>"` (per-representation — distinct for identity vs gzip, M-f); `Cache-Control` (`no-store` in dev / `public, max-age=3600` in prod); `Vary: Accept-Encoding` whenever a gzip variant exists, keyed off `gzipVariantExists` (not `serveGzip`) on both 200 and 304 (the AC-2 cache-poisoning fix); `X-Content-Type-Options: nosniff` on every 200/304 response; `Content-Security-Policy: sandbox` on the 200 for `image/svg+xml` and `text/html` (the SVG/HTML stored-XSS mitigation). (The `Rejected → 400` / `NotFound → 404` plain-text error responses carry neither header.)
6. **If-None-Match** compared against the **selected** representation's quoted ETag, parsed as a comma-list, `*` supported, weak comparison (`W/` stripped) per RFC 9110 §13.1.2. Match → **304**.
7. **304** is written by direct `res.status`/`res.body`/`res.headers` writes (never `set_content`), and it **erases** the body-framing headers (`Content-Length`, `Content-Type`, `Content-Encoding`) so the body-less 304 carries none of them (RFC 9110 §15.4.5 compliant; also satisfies RD-21). As of the HttpServer response-conformance fix the dispatcher already erases these for a body-less status, so these erases are defence-in-depth (APP-10). It keeps the validators (ETag/Cache-Control/Vary/nosniff).
8. **200** otherwise: the selected body (gzip with `Content-Encoding: gzip`, else identity) via `set_content`, plus the headers from step 5.

The bytes consumed in the response path are memory-safe under shared ownership (`StaticBlob::_entry`): filesystem/external bytes survive a concurrent `reload()`; embedded views point into static storage.

### Channels (RD-16 / RD-27)

```cpp
SseChannel& sseChannel(std::string_view name);   // get-or-create, stable reference
WsChannel&  wsChannel(std::string_view name);     // return-ref-only in v1
```

The registry is two `core::ConcurrentHashMap` maps — one keyed to `std::shared_ptr<SseChannel>`, one to `std::shared_ptr<WsChannel>` (there is no common `Channel` base type). `findOrInsert(name, factory)` runs the `make_shared` factory at most once under a shard write lock and returns a `shared_ptr` copy, so racing creators observe the **same** object and the object address never moves (the `shared_ptr` indirection survives map rehash). The authoritative usage model is setup-time creation; the `ConcurrentHashMap` backing additionally makes concurrent post-start creation race-free. The factory is allocation-only (no re-entrant registry call, no callback, no other lock) so the shard lock stays a strict leaf.

`wsChannel` returns the channel by reference only; the consumer attaches WS sessions manually via `WsChannel::subscribe(WebSocketServer&, SessionId)` (there is no `Application` WS subscribe route in v1). The `SseChannel`/`WsChannel` primitives themselves are documented in [sse_and_channels.md](../network/sse_and_channels.md).

### `subscribeRoute` — SSE wiring (RD-3 / RD-22 / RD-24)

```cpp
void subscribeRoute(std::string_view path, SseChannel& channel);
```

Registers a GET route whose handler calls the 4-arg `network::upgradeToSse(_http, req, res, onConnect)`. `upgradeToSse` writes the `200 + text/event-stream` preamble, takes over the session, and suppresses the dispatcher's terminal send so the socket stays open (the wire-level preamble and SSE stream mechanics are documented in [sse_and_channels.md](../network/sse_and_channels.md)). Inside `onConnect(stream)`, in strict order:

1. `_sseManager.add(stream)` **first** — `upgradeToSse` registers nothing with the manager; the consumer must. This arms the 15 s heartbeat lazily on the first stream, which keeps the reads-disabled SSE session alive past the `HttpServer` idle timeout.
2. `channel.subscribe(stream)`.
3. If metrics are enabled: `gauge->increment()` **then** `stream->onClose(decrement)`. The increment-strictly-before-register ordering relies on `SseStream::onClose` firing immediately if the stream is already closed at registration — so a peer disconnect in the gap still decrements (RD-22, no gauge leak). The allocating `add`/`subscribe` are sequenced before the increment, so a throw there cannot leave the gauge incremented-without-a-decrement; the `onClose` slot store is a small-closure move (no allocation).

### Metrics (OQ-8 / RD-28)

```cpp
void enableMetrics(std::string_view path = "/metrics");
```

Sets `_metricsEnabled` and registers a GET handler returning `MetricsRegistry::instance().prometheusExport()` with `Content-Type: text/plain; version=0.0.4; charset=utf-8`. Three series, reusing `core::MetricsRegistry` (no new metric subsystem):

| Series | Type | Labels | When |
|---|---|---|---|
| `web_request_duration_seconds` | Histogram (`DEFAULT_BUCKETS`) | `{route, status}` | per page/fragment/postFragment/serveStatic response |
| `web_responses_total` | Counter | `{route, status}` | per response |
| `web_sse_subscribers` | Gauge | `{channel}` | subscribe (+1) / close (−1) |

The two request series are resolved **per-(route,status) at observe time** (status is unknown until the response — they cannot be "resolved once"); the gauge has a fixed `{channel}` label and is resolved once at `subscribeRoute` registration and captured by pointer (the `Gauge&` is registry-singleton-owned, stable for process lifetime). `route` is the registration-time **pattern** captured by value (RD-25) — bounding cardinality. When metrics are disabled, handlers take a non-instrumented path with zero metric overhead.

> **Ordering note:** call `enableMetrics()` **before** `subscribeRoute()` — the SSE gauge is resolved at route-registration time, so a channel whose route was registered before metrics were enabled is not gauged. The request metrics are observe-time resolved and so are order-independent.

### `setDevMode` / `shutdown`

`setDevMode(bool)` stores `_devMode` (a `std::atomic<bool>`, relaxed) — atomic because handler threads read it while a setup/runtime flip writes it. In production (default false) a render failure yields a generic `Internal Server Error` 500 and static assets are `Cache-Control: public, max-age=3600`; in dev mode the 500 body carries `e.what()` + the offending template name and static assets are `no-store`.

`shutdown()` calls `_sseManager.shutdown()` (drain handshake, final `:shutting down` marker, close each live stream while the transport is up, cancel the schedule) and **must run before the transport teardown** (before/within `http.stop()`). The destructor calls it again idempotently. (A stream that connects during the teardown window — `add()`ed by a worker's `onConnect` between the manager's snapshot and its `clear()` — may not receive the final marker; its engine disconnect observer still fires `markClosed → onClose`, so there is no gauge leak.)

---

## 4. Usage Guide

### Quick start (the Hello-Admin shape)

```cpp
#include <iora/network/http_server.hpp>
#include <iora/core/timer.hpp>
#include <iora/web/assets.hpp>
#include <iora/web/application.hpp>

// Declaration order matters for safe teardown (see anti-patterns).
iora::web::Assets        assets = iora::web::Assets::fromDirectory("/srv/admin");
iora::core::TimerService timer;
timer.start();                             // returns a LifecycleResult — check .success in production
iora::network::HttpServer http;
http.setPort(8080);
iora::web::Application app(http, assets, timer);

app.enableMetrics();                       // before route/channel registration
app.serveStatic("/static/");               // /static/* -> /srv/admin/static

app.page("/", "index.html",
         [](const auto& req, auto& res, auto& data)
         {
           data["title"] = iora::parsers::Json("Admin");
         });

app.fragment("/rows", "rows.html",
             [&](const auto& req, auto& res, auto& data)
             {
               data["rows"] = loadRows();  // bare fragment for hx-get
             });

app.postFragment("/rows", "row.html",
                 [&](const auto& form, auto& res, auto& data)
                 {
                   if (form.count("name") == 0 || form.at("name").empty())
                   {
                     res.status = 400;
                   }
                   data["row"] = createRow(form);
                 });

auto& events = app.sseChannel("events");
app.subscribeRoute("/events", events);     // browser: new EventSource("/events")

http.start();
// ... run ...
app.shutdown();
http.stop();
timer.stop();
```

`events.publish("update", "<tr>...</tr>")` from any thread pushes an SSE event to all subscribers.

### Anti-patterns

- **Do NOT let `Assets`/`timer` be destroyed before the handler drain (APP-7).** With stack locals declared `http, assets, app`, reverse destruction destroys `app`, then `assets`, then `http` — destroying `Assets` *before* `http.stop()` drains handlers. Declare `assets`/`timer` first, or stop the server explicitly before scope exit.
- **Do NOT call `subscribeRoute()` before `enableMetrics()`** — the SSE gauge is resolved at route registration, so the channel is not gauged.
- **Do NOT construct two `Application`s over one `HttpServer` (APP-8)** — route/channel/metric ownership becomes ambiguous.
- **Do NOT move or copy an `Application`** — it is non-movable; do not `return` it by value or place it in a `std::vector`.
- **Do NOT expose `/metrics` unauthenticated on an untrusted network** — wrap it with `network::requireBasicAuth` (behind TLS) yourself if needed.

---

## 5. Call Flow / Sequence Reference

### SSE subscribe → publish

| Step | Actor | Action | Lock |
|---|---|---|---|
| 1 | worker | `subscribeRoute` handler → `upgradeToSse(_http, req, res, onConnect)` | HttpServer `_mutex` (narrowed, released before `onConnect`) |
| 2 | worker | preamble sent, session upgraded, `res._suppressSend = true` | — |
| 3 | worker | `onConnect`: `_sseManager.add(stream)` (arms 15 s heartbeat on first stream) | SseManager registry mutex (leaf) |
| 4 | worker | `channel.subscribe(stream)` | channel leaf mutex |
| 5 | worker | `gauge.increment()`; `stream.onClose(gauge.decrement)` | lock-free metric |
| 6 | worker | returns to pool; socket stays open | — |
| 7 | any | `channel.publish("update", "<tr>...</tr>")`: snapshot subscribers under leaf lock, release, `writeEvent` each open stream | channel leaf mutex held only for the snapshot |
| 8 | timer | every 15 s: heartbeat `": keepalive\n\n"` per stream | — |
| 9 | engine | on disconnect: `markClosed` → `onClose` → `gauge.decrement`; channel prunes | — |
| 10 | any | `app.shutdown()`: `": shutting down\n\n"` + `close()` per stream, then cancel schedule | SseManager drain handshake |

### serveStatic conditional request (gzip-cached client)

| Step | Action |
|---|---|
| 1 | `GET /static/app.js` (`Accept-Encoding: gzip`, `If-None-Match: "<gzipEtag>"`) |
| 2 | decode `pathRest` once → `app.js`; OQ-9 pre-check passes |
| 3 | `getStatic` → `Found` (blob: `rawEtag`, `gzipEtag`, `gzipVariantExists`) |
| 4 | `serveGzip = true`; `selectedEtag = gzipEtag` |
| 5 | `If-None-Match` matches `"<gzipEtag>"` → **304** |
| 6 | 304: erase `Content-Length`/`Content-Type`/`Content-Encoding`; set `ETag "<gzipEtag>"`, `Cache-Control`, `Vary: Accept-Encoding`, `nosniff`; empty body |

---

## 6. Thread Safety Model

| Operation | Safe to call from | Synchronization |
|---|---|---|
| ctor, `page`/`fragment`/`postFragment`/`serveStatic`/`subscribeRoute`/`enableMetrics`/`sseChannel`/`wsChannel` | main thread, setup window only | none needed (before `start()`) |
| registered handler bodies | `HttpServer` worker threads (concurrent) | read-only `_assets`; `_devMode`/`_metricsEnabled` atomic; per-request locals; metric observe is lock-free, get-or-create is registry-synchronized |
| `sseChannel`/`wsChannel` (post-start) | any thread | `ConcurrentHashMap::findOrInsert` (double-checked locking) |
| `channel.publish` | any thread | per-channel leaf mutex; snapshot-then-write (no lock during write) |
| `setDevMode` | any thread | `std::atomic<bool>` relaxed (best-effort visibility) |
| `shutdown` | any thread (once, before transport teardown) | `SseManager` draining/ticks-in-flight handshake; idempotent |

`Application` holds no lock of its own. No user callback is invoked while any lock is held. Lock ordering is a non-issue: `Application` never acquires two locks together; the registry/metrics/channel/manager locks are independent leaves.

---

## 7. Configuration Reference

| Parameter | Where | Default | Effect |
|---|---|---|---|
| `heartbeatInterval` | ctor 4th arg | `15000 ms` | SSE keepalive period; shorten in tests (M-1) |
| dev mode | `setDevMode(bool)` | `false` | 500 body verbosity + static `Cache-Control` |
| metrics | `enableMetrics(path)` | off; `path = "/metrics"` | enables the 3 web series + the `/metrics` endpoint |
| static prod cache | derived from dev mode | `public, max-age=3600` | `no-store` in dev |
| CSP for svg/html | fixed | `Content-Security-Policy: sandbox` | applied to `image/svg+xml`/`text/html` 200s |

---

## 8. API Reference

```cpp
namespace iora::web
{
class Application
{
public:
  using DataBuilder = std::function<void(const network::HttpServer::Request&,
                                         network::HttpServer::Response&, parsers::Json&)>;
  using FormHandler =
    std::function<void(const std::unordered_map<std::string, std::string>& form,
                       network::HttpServer::Response&, parsers::Json&)>;

  Application(network::HttpServer& http, Assets& assets, core::TimerService& timer,
              std::chrono::milliseconds heartbeatInterval = std::chrono::milliseconds(15000));
  ~Application();                              // idempotent _sseManager.shutdown()
  Application(const Application&) = delete;    // non-copyable
  Application& operator=(const Application&) = delete;
  Application(Application&&) = delete;         // non-movable
  Application& operator=(Application&&) = delete;

  std::string render(std::string_view templateName,
                     const parsers::Json& data) const; // throws, sets no status

  void page(std::string_view path, std::string_view templateName, DataBuilder build);
  void fragment(std::string_view path, std::string_view templateName, DataBuilder build);
  void postFragment(std::string_view path, std::string_view templateName, FormHandler handle);
  void serveStatic(std::string_view prefix);

  SseChannel& sseChannel(std::string_view name);
  WsChannel&  wsChannel(std::string_view name);
  void subscribeRoute(std::string_view path, SseChannel& channel);

  void enableMetrics(std::string_view path = "/metrics");
  void setDevMode(bool dev);
  void shutdown();                             // call before http.stop()
};
}
```

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| **APP-1 / APP-11 / RD-26:** `Application` owns no thread; `SseManager` rides an injected `core::TimerService` (4th ctor arg) | `IoraService` exposes no timer accessor; injection keeps the no-thread invariant. The consumer's `onConnect` must register streams with the manager — `upgradeToSse` does not. |
| **RD-27:** channel registry is `ConcurrentHashMap` in v1 (not a plain map) | Makes both setup-time and concurrent post-start creation race-free; the factory runs once and racing creators share one object. |
| **RD-28 / OQ-5:** `_devMode`/`_metricsEnabled` are `std::atomic<bool>`; request metrics resolved per-(route,status) at observe time | A plain-bool read on worker threads while flipped is a data race; a per-response-varying `status` label cannot be resolved once. |
| **RD-21 / RFC 9110 §15.4.5:** 304 by direct field writes; strip `Content-Length`/`Content-Type`/`Content-Encoding` | A body-less 304 must carry none of them; a non-empty 200 body means `Content-Length: 0` would be non-compliant. |
| **web M-1 / web L-1 / M-f:** select representation first (q-value aware), then compare If-None-Match against the selected ETag; distinct per-representation ETags | A gzip-cached client revalidating with the gzip ETag must still get a 304; a naive `contains("gzip")` would serve a `gzip;q=0`-refused encoding and break the identity-cached client's 304. |
| **web H-1:** `nosniff` on every 200/304 static response; `CSP: sandbox` for SVG/HTML 200s | SVG can carry active content (`<script>`, `on*`, `<foreignObject>`); `sandbox` neutralizes it on direct navigation without breaking inline `<img>` SVG. |
| **OQ-11 / APP-4:** `PartialResolver` injected only in `render` | Keeps the only `parsers/`↔`web/` edge a forward one; no include cycle. |

---

## 10. Known Limitations

- No automatic route discovery — every route/channel is registered explicitly during setup.
- Single `Application` per `HttpServer` (APP-8); two is unsupported.
- The consumer must keep `Assets` and the `TimerService` alive through the in-flight-handler drain (APP-7).
- Web metrics are off unless `enableMetrics()` is called; the label set is fixed (`{route,status}` / `{channel}`). The SSE gauge requires `enableMetrics()` before `subscribeRoute()`. Only the `page`/`fragment`/`postFragment`/`serveStatic` handlers are instrumented — `subscribeRoute`'s SSE handler and the `/metrics` endpoint itself are not counted, and `HttpServer`-level rejections (404 for unregistered paths, 405, 413/431, the routing safety-net 500) are not included.
- `/metrics` is unauthenticated by default.
- Static asset filenames containing a literal `/` or `\` are not addressable (the exactly-once-decode traversal-safety tradeoff).
- `serveStatic` never emits `406 Not Acceptable`: a client that refuses all codings (`Accept-Encoding: identity;q=0` or `*;q=0`) is still served the identity representation. This is a deliberate RFC 9110 §12.5.3 SHOULD-deviation — the common pragmatic choice (mainstream servers behave the same), never a torn or wrong body.
- `CSP: sandbox` is applied uniformly to every SVG/HTML static asset (no per-asset opt-out in v1); a static HTML page that must run inline scripts will be sandboxed.
- The 200 body is copied into `Response::body` per request (`HttpServer::Response::body` is a `std::string`); a zero-copy view/move setter is a tracked follow-on.
- Full authentication (sessions/CSRF/login/OIDC/LDAP) is not implemented here. `Application` provides no auth wiring; the pluggable auth **contracts** (`IAuthGuard`/`ISessionStore`/`ICsrfProtector`/`ILoginUiProvider`) are documented in [middleware_interfaces.md](middleware_interfaces.md), and a concrete implementation is the consumer's (or an external middleware's) responsibility.
