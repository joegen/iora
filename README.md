# Iora

Iora is a C++17 foundation library for building networked services on Linux. It supplies the plumbing a server process needs: an epoll-based TCP/UDP/TLS transport, an HTTP client and server, WebSocket and Server-Sent Events, a DNS client (including RFC 3263 service discovery), JSON-RPC 2.0, JSON / XML / TOML / Mustache / HEP3 parsers, concurrency and timer primitives, logging and Prometheus-style metrics, rate limiting and circuit breaking, a gzip codec, secure random, hashing and UUIDs, process execution, persistent key-value storage, and a server-rendered (HTMX) web application layer. It has no third-party runtime dependency other than OpenSSL.

Most of the library is header-only. A small shared library, `libiora_core`, holds the process-wide singletons (logger, metrics registry, the blocking-I/O and general async thread pools, the JsonFileStore background flusher, the `IoraService` instance) so that every module in a process, including dynamically loaded plugins, shares one instance. On top of the library sits an optional runtime: `IoraService` and the `iora` host executable load plugins as shared libraries and manage their lifecycle, configuration, HTTP routes, and exported APIs.

The name comes from the Common Iora, a small, agile songbird of Southeast Asia. It is also a recursive acronym: **Iora Orchestrates Routing Asynchronously**.

## Requirements

- Linux (the transport and timers use `epoll`, `eventfd`, and `timerfd`)
- A C++17 compiler and CMake 3.14 or newer (the `cmake --install` and `ctest --test-dir` commands below need 3.15 and 3.20 respectively)
- OpenSSL (`libssl`, `libcrypto`) and POSIX threads, both required
- Catch2 v2.13.10, fetched from GitHub at configure time unless that exact version is already installed. This currently happens even with `-DBUILD_TESTS=OFF`, so an offline configure needs Catch2 pre-installed, built with `CATCH_BUILD_STATIC_LIBRARY=ON` (it must provide `Catch2::Catch2WithMain`, otherwise configure fails)

## Quick start

A minimal HTTP service built on the library alone, with no `IoraService`:

```cpp
#include "iora/network/http_server.hpp"
#include "iora/parsers/json.hpp"

#include <iostream>

int main()
{
  iora::network::HttpServer server("0.0.0.0", 8080);

  server.onGet("/hello",
               [](const iora::network::HttpServer::Request &,
                  iora::network::HttpServer::Response &res)
               {
                 iora::parsers::Json body = iora::parsers::Json::object();
                 body["message"] = "hello from iora";
                 res.set_content(body.dump(), "application/json");
               });

  try
  {
    server.start(); // throws if the port cannot be bound
  }
  catch (const std::exception &e)
  {
    std::cerr << e.what() << '\n';
    return 1;
  }
  std::cin.get(); // serve until Enter is pressed
  server.stop();
  return 0;
}
```

```bash
g++ -std=c++17 -DIORA_CORE_SHARED -I/usr/local/include hello.cpp -o hello \
    -L/usr/local/lib -liora_core -lssl -lcrypto -pthread
```

To build a plugin for the `iora` host instead, derive from `iora::IoraService::Plugin`, implement `onLoad` / `onUnload`, and export it with `IORA_DECLARE_PLUGIN(MyPlugin)`. The runtime, its configuration file, and the plugin model are covered in [`docs/iora_service.md`](docs/iora_service.md) and [`docs/core/plugin_loader.md`](docs/core/plugin_loader.md). A complete sample plugin lives in [`sample/plugins/`](sample/plugins/).

## Build

```bash
cmake -S . -B build
cmake --build build
```

Useful options: `-DBUILD_SAMPLES=OFF`, `-DBUILD_EXAMPLES=OFF` (the flagship programs in [`examples/`](examples/)), and `-DBUILD_TESTS=OFF`.

### Tests

Test groups roughly follow `include/iora/` and are all off by default. Enable one group with `-DIORA_BUILD_<GROUP>_TESTS=ON` (`NETWORK`, `CORE`, `PARSERS`, `UTIL`, `STORAGE`, `SERVICE`, `WEB`, `RPC`, `DEBUG`), or all of them with `-DIORA_BUILD_ALL_TESTS=ON`:

```bash
cmake -S . -B build -DIORA_BUILD_ALL_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

### Install

```bash
sudo cmake --install build
```

This installs the headers, `libiora_core`, the CMake package (`Iora::` targets plus the `iora_embed_assets()` helper), the `iora` host executable, the vendored `htmx.min.js`, and a default `iora.cfg` under `<prefix>/etc/iora.conf.d/` (an existing file is not overwritten; `<prefix>` here is the one given at configure time, `cmake --install --prefix` does not move this file). The `iora` executable looks for `/etc/iora.conf.d/iora.cfg` by default; pass `--config <file>` when the install prefix is not `/`.

## Linking

Consumers link `libiora_core`, OpenSSL, and threads. `Iora::iora_lib` adds `IORA_CORE_SHARED` for you; outside CMake, define it yourself so the headers use the shared singletons. Omitting `IORA_CORE_SHARED` while linking `libiora_core` compiles duplicate per-image singletons (an ODR violation). After a system install run `sudo ldconfig` (or link with `-Wl,-rpath,<prefix>/lib`) so the loader finds `libiora_core.so.1`; the library directory is `<prefix>/lib` or `<prefix>/lib64` depending on the platform's GNUInstallDirs. On glibc older than 2.34 every link against `libiora_core` also needs `-ldl`.

CMake, from an installed package:

```cmake
find_package(Iora REQUIRED)
target_link_libraries(my_app PRIVATE Iora::iora_lib OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
```

Makefile / Autoconf: use the same flags as the quick-start compile line, with `<prefix>` in place of `/usr/local`.

## Documentation

Every public component has an Architecture & Programmer's Guide under [`docs/`](docs/), grouped by area to mirror `include/iora/`. This section is the index.

Each guide opens with a `Back to index` link to this README. The header-to-guide map lives in [`docs/manifest.json`](docs/manifest.json).

### Runtime / Getting Started
- **IoraService** — the framework entry point: service lifecycle, Config reference, route/event builders, the exported-API drain-gate/SafeApiFunction model, plugin orchestration — [`docs/iora_service.md`](docs/iora_service.md)
- **PluginLoader / PluginManager** — dynamic plugin loading (dlopen/dlclose) and multi-plugin lifecycle — [`docs/core/plugin_loader.md`](docs/core/plugin_loader.md)

### rpc
- **JSON-RPC (client / HTTP endpoint / server)** — RFC-conformant JSON-RPC 2.0 over HTTP with negotiated gzip content-coding — [`docs/rpc/jsonrpc.md`](docs/rpc/jsonrpc.md)

### core
- **ServiceRegistry** — type-erased, thread-safe module/service registry (drain-before-unload invariant) — [`docs/core/service_registry.md`](docs/core/service_registry.md)
- **Logger** — thread-safe async logging with file rotation, gzip compression, and external handlers — [`docs/core/logger.md`](docs/core/logger.md)
- **ThreadPool** (`core::async` / `PooledFuture`) — worker pool with lifecycle drain plus the `std::async` drop-in — [`docs/core/thread_pool.md`](docs/core/thread_pool.md)
- **TimerService** — single-`timerfd` + min-heap timer service (one-shot and periodic) — [`docs/core/timer.md`](docs/core/timer.md)
- **TimingWheel** — hierarchical timing-wheel scheduler behind the `ITimerService` seam — [`docs/core/timing_wheel.md`](docs/core/timing_wheel.md)
- **BlockingQueue** — bounded thread-safe blocking FIFO (blocking, timed, and non-blocking ops; close/drain) — [`docs/core/blocking_queue.md`](docs/core/blocking_queue.md)
- **EventQueue** — worker-pool event dispatcher with id / name / regex-pattern handler routing — [`docs/core/event_queue.md`](docs/core/event_queue.md)
- **RingBuffer** — SPSC lock-free ring buffer, fixed and dynamic (acquire/release ordering) — [`docs/core/ring_buffer.md`](docs/core/ring_buffer.md)
- **ConcurrentHashMap** — lock-striped concurrent hash map (sharded `shared_mutex`, in-place callbacks) — [`docs/core/concurrent_hash_map.md`](docs/core/concurrent_hash_map.md)
- **Buffer primitives** (`BufferView` / `BufferWriter` / `MutableBufferView`) — zero-copy byte views with network byte-order readers/writers — [`docs/core/buffer_primitives.md`](docs/core/buffer_primitives.md)
- **RateLimiter** (`TokenBucket` / `SlidingWindowCounter` / `RateLimiterMap`) — token-bucket and sliding-window rate limiting — [`docs/core/rate_limiter.md`](docs/core/rate_limiter.md)
- **Result** (`Result<T, E>`) — monadic success/error value type (ok/err, map/andThen/mapError, ref-qualified accessors) — [`docs/core/result.md`](docs/core/result.md)
- **StringUtils** — ASCII, locale-independent string helpers (split/trim, case-insensitive compare/hash) — [`docs/core/string_utils.md`](docs/core/string_utils.md)
- **StateMachine** — builder-configured finite state machine (guards, actions, transition hooks) — [`docs/core/state_machine.md`](docs/core/state_machine.md)
- **Signal** — typed signal/slot with COW slot list, `weak_ptr` auto-disconnect, and `ScopedConnection` RAII — [`docs/core/signal.md`](docs/core/signal.md)
- **Metrics** (`Counter` / `Gauge` / `Histogram` / `MetricsRegistry`) — lock-free metric observation (shared_mutex registry) with Prometheus / JSON export — [`docs/core/metrics.md`](docs/core/metrics.md)
- **ConfigLoader** — TOML-backed configuration loader with typed getters and reload — [`docs/core/config_loader.md`](docs/core/config_loader.md)
- **Atomic primitives** (`AtomicSharedPtr` / `AtomicThreadId`) — a non-copyable wrapper that forces every `shared_ptr` access through the C++17 atomic free functions, and a stamp/compare thread-id holder for teardown and self-join guards — [`docs/core/atomic_primitives.md`](docs/core/atomic_primitives.md)
- **errno_utils** (`errnoMessage`) — thread-safe `errno`-to-message conversion (`strerror_r` wrapper) — [`docs/core/errno_utils.md`](docs/core/errno_utils.md)

### network
- **Transport** — the unified TCP/UDP transport facade: engines, async + synchronous operations, TLS client identity, DSCP marking, and read-gating — [`docs/network/transport.md`](docs/network/transport.md)
  - **Transport sync-op lifecycle** — `connectSync` / `receiveSync` / `sendSync`, the drain-before-close teardown handshake, the pending-sync-op cap, and the timeout sentinels — [`docs/network/transport_sync_lifecycle.md`](docs/network/transport_sync_lifecycle.md)
  - **NameResolver / DNS host resolution** — off-thread `getaddrinfo` host resolution and per-connection TLS identity threaded through the resolve/resume (also the `NameResolver` vs `DnsClient` boundary) — [`docs/network/transport_dns_resolution.md`](docs/network/transport_dns_resolution.md)
- **HttpClient / HttpClientPool** — the synchronous HTTP client and its bounded connection pool: TLS client identity, timeouts and slow-peer hardening, case-insensitive schemes, IPv6-literal authorities, and pooled async — [`docs/network/http_client.md`](docs/network/http_client.md)
- **HttpServer / WebhookServer** — the routing HTTP server and its JSON specialization: request framing and chunked de-chunking, RFC 9112 connection persistence, repeated Set-Cookie, and the WebSocket-upgrade subclass seam — [`docs/network/http_server.md`](docs/network/http_server.md)
- **HTTP Basic Auth** — the `requireBasicAuth` route decorator: realm sanitization, constant-time verification, and credential scrubbing — [`docs/network/http_basic_auth.md`](docs/network/http_basic_auth.md)
- **WebSocket** — the RFC 6455 frame codec, server, and client: tri-state frame parse with length/masking/RSV/control-frame conformance, fragmentation, and the abrupt-disconnect close hook — [`docs/network/websocket.md`](docs/network/websocket.md)
- **Network Resiliency: CircuitBreaker & ConnectionHealth** — standalone circuit-breaking and per-connection health primitives (not auto-wired by the transport): the Closed/Open/HalfOpen breaker and its `std::string`-name-keyed manager, plus the five-level connection-health tracker and its `SessionId`-keyed monitor — [`docs/network/resiliency.md`](docs/network/resiliency.md)
- **DnsClient** — the standalone DNS-protocol client with RFC 3263 SIP service discovery (NAPTR→SRV→A/AAAA, `S`/`A`-flag subset), UDP-with-TCP-fallback transport, retry/backoff, hardened wire parsing, TTL caching, and best-effort cancellable async — distinct from the transport-internal `NameResolver`/`getaddrinfo` path — [`docs/network/dns_client.md`](docs/network/dns_client.md)
- **Server-Sent Events + Channel pub/sub** — the `SessionId`-retention SSE model (`upgradeToSse`, `SseStream`, the injected-`TimerService` `SseManager` heartbeat) plus the `SseChannel` / `WsChannel` snapshot-then-write fan-out — [`docs/network/sse_and_channels.md`](docs/network/sse_and_channels.md)
- **EventBatchProcessor** — the optional epoll batch-drain helper with adaptive sizing and the eventfd/timerfd special-fd fast-path (opt-in via `TransportConfig::batching`) — [`docs/network/event_batch_processor.md`](docs/network/event_batch_processor.md)
- **IP utilities** — IPv4/IPv6 parsing, validation, classification, CIDR containment, and the `shared_mutex`-guarded trusted-network allow-list (leading-zero rejection, RFC 5952 rendering) — [`docs/network/ip_utils.md`](docs/network/ip_utils.md)
- **ObjectPool** — the generic mutex-guarded free-list pool with capped growth and the `PooledObject` RAII return-to-pool handle — [`docs/network/object_pool.md`](docs/network/object_pool.md)
- **SockaddrUtils** — the shared `sockaddr_storage` ↔ `TransportAddress` conversions and DSCP fd-marking with dual-stack mirroring — [`docs/network/sockaddr_utils.md`](docs/network/sockaddr_utils.md)

### parsers
- **JSON** — value model, parser & serializer (`\uXXXX`/surrogate decoding, RFC 8259) — [`docs/parsers/json.md`](docs/parsers/json.md)
- **XML** — pull/SAX/DOM parser with numeric char-ref decoding — [`docs/parsers/xml.md`](docs/parsers/xml.md)
- **MinimalToml** — parser & serializer for the config subset — [`docs/parsers/minimal_toml.md`](docs/parsers/minimal_toml.md)
- **Mustache** — logic-less template engine (escape-by-default) — [`docs/parsers/mustache.md`](docs/parsers/mustache.md)
- **HtmlEscape / URL & Form encoding** — HTML escaping plus percent/form encode/decode and form-body parsing — [`docs/parsers/html_escape.md`](docs/parsers/html_escape.md)
- **HttpMessage** — HTTP request/response model (parse / serialize / build), `iora::network` namespace; cross-linked from the network HTTP guides — [`docs/parsers/http_message.md`](docs/parsers/http_message.md)
- **AcceptEncoding** — RFC 9110 gzip acceptability (q-values) — [`docs/parsers/accept_encoding.md`](docs/parsers/accept_encoding.md)
- **ContentCoding** — Content-Encoding list-splitting and log scrubbing — [`docs/parsers/content_coding.md`](docs/parsers/content_coding.md)
- **HEP3** — non-throwing parser for the HEP v3 (sipcapture) capture envelope: bounded chunk walk to typed metadata, payload classified but not decoded — [`docs/parsers/hep3.md`](docs/parsers/hep3.md)

### util
- **Gzip** — the dependency-free RFC 1951/1952 DEFLATE+gzip codec: one-shot `compress`, the streaming `Gzip::Encoder`, and bounded-output `decompress` of untrusted input (zip-bomb cap, `core::Result` errors) — [`docs/util/gzip.md`](docs/util/gzip.md)
- **Caching (TtlMap / ExpiringCache)** — two TTL caches: the read-optimized `TtlMap` (injected `TimerService`, `shared_mutex`, bounded approximate-LRU, chunked non-stalling sweeper) and the simpler thread-owning `ExpiringCache` with eviction callbacks — [`docs/util/caching.md`](docs/util/caching.md)
- **ExternalClockIdleMap** — a caller-clocked idle-timeout map with an optional LRU bound and eviction callback; no background thread and no internal lock (the caller serializes access) — [`docs/util/external_clock_idle_map.md`](docs/util/external_clock_idle_map.md)
- **Base64** — RFC 4648 standard (`Base64`, padded, strict canonical decode) and URL-safe unpadded (`Base64Url`) encoders/decoder — [`docs/util/base64.md`](docs/util/base64.md)
- **Crc32** — table-driven reflected CRC-32 (`compute` + the streaming `Incremental` accumulator) used by the gzip trailer — [`docs/util/crc32.md`](docs/util/crc32.md)
- **Filesystem** — small executable-path and current-directory file-cleanup helpers (`getExecutablePath`/`getExecutableDir`, anchored-prefix / fragment file removal) — [`docs/util/filesystem.md`](docs/util/filesystem.md)
- **Unicode** — the shared UTF-8 code-point encoder (`appendUtf8`) and ASCII hex-digit decoder (`hexDigitValue`) used by the JSON/XML parsers and URL decoding — [`docs/util/unicode.md`](docs/util/unicode.md)

### web
- **Channel** (SSE/WS pub-sub) — documented alongside the SSE stream in [`docs/network/sse_and_channels.md`](docs/network/sse_and_channels.md)
- **Application** — the consumer-facing facade wiring routing, Mustache, assets, SSE/WS channels, and metrics into a server-rendered HTMX app — [`docs/web/application.md`](docs/web/application.md)
- **Asset pipeline** (`Assets`) — static-asset + template serving with build-time embedding, gzip variants, per-representation ETags, and a path-traversal chokepoint — [`docs/web/asset_pipeline.md`](docs/web/asset_pipeline.md)
- **Htmx** — `HX-*` request inspectors and response setters with CR/LF + dangerous-scheme injection guards — [`docs/web/htmx.md`](docs/web/htmx.md)
- **Middleware interfaces** — the pluggable auth/session/CSRF/login contracts (`IAuthGuard`/`ISessionStore`/`ICsrfProtector`/`ILoginUiProvider`) and their conformance suites — [`docs/web/middleware_interfaces.md`](docs/web/middleware_interfaces.md)

### storage
- **KVStore** — durable binary key-value store with per-key TTL, background compaction, and an in-memory mode — [`docs/storage/kvstore.md`](docs/storage/kvstore.md)
- **JsonFileStore** — JSON-file-backed store with typed values and a shared background flush thread — [`docs/storage/json_file_store.md`](docs/storage/json_file_store.md)
- **ConcreteStateStore** — lightweight in-memory, case-insensitive string state map — [`docs/storage/concrete_state_store.md`](docs/storage/concrete_state_store.md)

### crypto / ids / system / common
- **SecureRng** — OpenSSL-backed secure random bytes plus the SHA-1 / SHA-256 / HMAC-SHA-256 one-shot helpers — [`docs/crypto/secure_rng.md`](docs/crypto/secure_rng.md)
- **Uuid** — RFC 9562 v4 (random) and v7 (Unix-ms time-ordered) UUID strings — [`docs/ids/uuid.md`](docs/ids/uuid.md)
- **ShellRunner** — shell command execution and RAII background-process management (`ProcessHandle`) — [`docs/system/shell_runner.md`](docs/system/shell_runner.md)
- **ILifecycleManaged** — the start / drain / stop / reset lifecycle contract implemented by `ThreadPool` and `TimerService` — [`docs/common/i_lifecycle_managed.md`](docs/common/i_lifecycle_managed.md)

## License

Iora is licensed under the [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/).
