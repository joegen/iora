// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Request-direction tests for the JSON-RPC bidirectional negotiated-gzip
// Consumer C (tracker 2026-09-04-3, arch architecture/iora/jsonrpc_gzip_compression.json).
// Phase 2: the CLIENT compresses request bodies (config-driven, over threshold)
// and the real SERVER decodes them, with the 415 safety-net (single latch-off +
// TTL re-probe) as the fallback.
//
// Two independent surfaces are exercised:
//   * SERVER decode (task-1.x): the real mod_jsonrpc_server .so is loaded with a
//     chosen config (enableRequestDecompression / requireAuth via a TOML
//     configFile) and driven with a raw HttpClient that sets crafted
//     Content-Encoding headers + gzipped bodies. Validates handlePost end-to-end.
//   * CLIENT compress + safety-net (task-2.x): a JsonRpcClient is constructed
//     directly and pointed at a controllable /capture webhookServer handler whose
//     policy decides 200 vs 415 and records the wire request, so the compress
//     decision, the typed 415 retry, the latch, and the TTL re-probe are all
//     black-box observable. A tiny test-access seam force-expires a latch's TTL.
//
// Duplicate Content-Encoding / Accept-Encoding FIELD-LINE combining (RFC 9110
// §5.3) is validated end-to-end through the real ingress parser in the foundation
// suite (iora_test_jsonrpc_gzip_foundation, "real ingress path combines duplicate
// encodings"); this slice's new server logic consumes the ALREADY-combined value,
// which is exercised here via comma-combined single-line values.

#include "../jsonrpc_client.hpp" // JsonRpcClient, Config, ContentCodingRejectedError

#include "iora/iora.hpp"
#include "iora/network/http_client.hpp"
#include "iora/parsers/http_message.hpp" // normalizeOrigin
#include "iora/util/gzip.hpp"

#include <catch2/catch.hpp>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace iora::modules::connectors;

// ─────────────────────────────────────────────────────────────────────────────
// Test-access seam: reach the per-origin request-compression cache to force-expire
// a latch's TTL (deterministic re-probe test) and observe latch state. Defined in
// the befriended namespace so it can reach JsonRpcClient::_impl and Impl's private
// _requestCompressionState / _requestCompressionMutex.
// ─────────────────────────────────────────────────────────────────────────────
namespace iora
{
namespace modules
{
namespace connectors
{
struct JsonRpcClientTestAccess
{
  static void expireRequestCompressionTtl(JsonRpcClient &c, const std::string &origin)
  {
    std::lock_guard<std::mutex> lk(c._impl->_requestCompressionMutex);
    auto it = c._impl->_requestCompressionState.find(origin);
    if (it != c._impl->_requestCompressionState.end())
    {
      it->second.ttlExpiry = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    }
  }

  static bool isRequestOriginLatchedOff(JsonRpcClient &c, const std::string &origin)
  {
    std::lock_guard<std::mutex> lk(c._impl->_requestCompressionMutex);
    auto it = c._impl->_requestCompressionState.find(origin);
    return it != c._impl->_requestCompressionState.end() && it->second.latchedOff;
  }

  // Direct drivers for the two cache access sites, so a concurrency probe can
  // hammer the exact synchronized read/write paths without HTTP flakiness.
  static bool callShouldCompress(JsonRpcClient &c, const std::string &origin)
  {
    return c._impl->shouldCompressOrigin_(origin);
  }
  static void callLatchOff(JsonRpcClient &c, const std::string &origin)
  {
    c._impl->latchOff_(origin);
  }
};
} // namespace connectors
} // namespace modules
} // namespace iora

namespace
{

using Headers = std::map<std::string, std::string>;
using JsonHandler = std::function<iora::parsers::Json(const iora::parsers::Json &)>;

std::string gz(const std::string &s) { return iora::util::Gzip::compress(s); }

const char *const kReqJson =
  R"({"jsonrpc":"2.0","method":"echo","params":{"x":"hello-world"},"id":1})";
const char *const kOkResult = R"({"jsonrpc":"2.0","result":{"ok":true},"id":1})";
const char *const kUnsupportedCodingBody =
  R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Unsupported Content-Encoding"},"id":null})";

/// Minimal raw-socket HTTP request to a loopback port (used to send an OPTIONS
/// preflight — HttpClient exposes no OPTIONS method). Returns the raw response,
/// or "" on any socket error.
std::string rawHttpRequest(int port, const std::string &requestBytes)
{
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    return "";
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<std::uint16_t>(port));
  addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");
  std::string out;
  if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0 &&
      ::send(fd, requestBytes.data(), requestBytes.size(), 0) ==
        static_cast<ssize_t>(requestBytes.size()))
  {
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0)
    {
      out.append(buf, static_cast<std::size_t>(n));
    }
  }
  ::close(fd);
  return out;
}

std::string serverPluginPath()
{
  return iora::util::resolveRelativePath(iora::util::getExecutableDir(),
                                         "../../../endpoints/jsonrpc_server/") +
         "/mod_jsonrpc_server.so";
}

std::string writeServerToml(bool decode, bool auth)
{
  namespace fs = std::filesystem;
  static int seq = 0;
  const std::string path =
    (fs::temp_directory_path() / ("iora_gzip_req_server_" + std::to_string(seq++) + ".toml"))
      .string();
  std::ofstream o(path, std::ios::trunc);
  o << "[iora.modules.jsonrpc_server]\n";
  o << "enableRequestDecompression = " << (decode ? "true" : "false") << "\n";
  o << "requireAuth = " << (auth ? "true" : "false") << "\n";
  o.close();
  return path;
}

iora::IoraService::Config baseConfig(int port)
{
  iora::IoraService::Config c;
  c.server.port = port;
  c.log.level = "info";
  c.modules.autoLoad = false;
  return c;
}

/// Start a fresh IoraService with the real jsonrpc server plugin at the chosen
/// config, register an echo method, and wait for the listener.
iora::IoraService &startServer(int port, bool decode, bool auth)
{
  try
  {
    iora::IoraService::shutdown();
  }
  catch (...)
  {
  }
  auto cfg = baseConfig(port);
  cfg.configFile = writeServerToml(decode, auth);
  iora::IoraService::init(cfg);
  iora::IoraService &svc = iora::IoraService::instanceRef();

  REQUIRE(std::filesystem::exists(serverPluginPath()));
  REQUIRE(svc.loadSingleModule(serverPluginPath()));

  svc.callExportedApi<void, const std::string &, JsonHandler>(
    "jsonrpc.register", "echo", [](const iora::parsers::Json &p) { return p; });

  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  return svc;
}

// ── /capture handler state (client-side tests) ──────────────────────────────
struct Capture
{
  std::mutex m;
  int count = 0;
  std::vector<std::string> ce;   // Content-Encoding per request ("" if absent)
  std::vector<std::string> ct;   // Content-Type per request
  std::vector<std::string> body; // raw body per request
  // policy(idx, compressed, res): decide the response. Default: 200 + kOkResult.
  std::function<void(int, bool, iora::network::WebhookServer::Response &)> policy;

  void reset()
  {
    std::lock_guard<std::mutex> lk(m);
    count = 0;
    ce.clear();
    ct.clear();
    body.clear();
    policy = nullptr;
  }
};
Capture g_cap;

iora::IoraService &startCaptureService(int port)
{
  try
  {
    iora::IoraService::shutdown();
  }
  catch (...)
  {
  }
  iora::IoraService::init(baseConfig(port));
  iora::IoraService &svc = iora::IoraService::instanceRef();
  g_cap.reset();

  svc.webhookServer()->onPost(
    "/capture",
    [](const iora::network::WebhookServer::Request &req,
       iora::network::WebhookServer::Response &res)
    {
      std::lock_guard<std::mutex> lk(g_cap.m);
      const int idx = g_cap.count++;
      const std::string ceVal = req.get_header_value("Content-Encoding");
      g_cap.ce.push_back(ceVal);
      g_cap.ct.push_back(req.get_header_value("Content-Type"));
      g_cap.body.push_back(req.body);
      const bool compressed = !ceVal.empty();
      if (g_cap.policy)
      {
        g_cap.policy(idx, compressed, res);
      }
      else
      {
        res.status = 200;
        res.set_content(kOkResult, "application/json");
      }
    });

  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  return svc;
}

Config clientCompressionConfig(bool enable, std::size_t threshold)
{
  Config cfg;
  cfg.enableRequestCompression = enable;
  cfg.compressionThreshold = threshold;
  cfg.maxRetries = 3;
  return cfg;
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// SERVER decode — enableRequestDecompression=true, requireAuth=false (task-1.x,
// task-3.3 server). Driven with a raw HttpClient against the real /rpc plugin.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request server: decode enabled round-trip + list handling",
          "[gzip-request][server]")
{
  iora::IoraService &svc = startServer(8139, /*decode=*/true, /*auth=*/false);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  iora::network::HttpClient http;
  const std::string url = "http://localhost:8139/rpc";
  const std::string reqJson = kReqJson;

  SECTION("gzip request decodes and routes (task-1.3)")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("identity request (no Content-Encoding) routes normally")
  {
    auto r = http.post(url, reqJson, {{"Content-Type", "application/json"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("stacked 'gzip, gzip' double-decodes (task-1.1)")
  {
    auto r = http.post(url, gz(gz(reqJson)),
                       {{"Content-Type", "application/json"},
                        {"Content-Encoding", "gzip, gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("two physical Content-Encoding lines combine (§5.3) then double-decode (task-3.3)")
  {
    // End-to-end composition of the foundation §5.3 combine (two Content-Encoding
    // field-lines -> "gzip, gzip") with THIS slice's decode. HttpClient's map API
    // cannot emit duplicate header lines, so drive it over the raw socket (cpp17
    // L-3 / web F3 seam). Body is double-gzipped so the combined "gzip, gzip"
    // decodes it back to the original JSON.
    const std::string doubled = gz(gz(reqJson));
    const std::string reqBytes = "POST /rpc HTTP/1.1\r\n"
                                 "Host: localhost:8139\r\n"
                                 "Content-Type: application/json\r\n"
                                 "Content-Encoding: gzip\r\n"
                                 "Content-Encoding: gzip\r\n"
                                 "Content-Length: " +
                                 std::to_string(doubled.size()) +
                                 "\r\n"
                                 "Connection: close\r\n\r\n" +
                                 doubled;
    const std::string resp = rawHttpRequest(8139, reqBytes);
    REQUIRE(resp.find("HTTP/1.1 200") != std::string::npos);
    REQUIRE(resp.find("hello-world") != std::string::npos);
  }

  SECTION("'identity, gzip' decodes (identity is a no-op) (task-1.1)")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "identity, gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("empty list elements are skipped 'gzip,,' (§5.6.1) (task-1.1)")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "gzip,,"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("'x-gzip' is a decode-side alias of gzip (§8.4.1) (task-1.1)")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "x-gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("coding token is ASCII case-insensitive 'GZIP' (task-1.1)")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "GZIP"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("identity-only decodable even with a coding present (task-1.2)")
  {
    auto r = http.post(url, reqJson, {{"Content-Type", "application/json"},
                                      {"Content-Encoding", "identity"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("unknown coding -> 415 whose Accept-Encoding lists gzip AND identity (task-1.2)")
  {
    auto r = http.post(url, reqJson, {{"Content-Type", "application/json"},
                                      {"Content-Encoding", "br"}}, 0);
    REQUIRE(r.statusCode == 415);
    auto it = r.headers.find("Accept-Encoding");
    REQUIRE(it != r.headers.end());
    REQUIRE(it->second == "gzip, identity");
  }

  SECTION(">2 stacked codings -> 415 (not 500), still with Accept-Encoding (task-1.2 over-cap)")
  {
    auto r = http.post(url, gz(gz(gz(reqJson))),
                       {{"Content-Type", "application/json"},
                        {"Content-Encoding", "gzip, gzip, gzip"}}, 0);
    REQUIRE(r.statusCode == 415);
    // DP-7: EVERY undecodable 415 — including the over-cap branch — carries the
    // Accept-Encoding decodable set, else the client latch-off would not fire (web F1).
    auto it = r.headers.find("Accept-Encoding");
    REQUIRE(it != r.headers.end());
    REQUIRE(it->second == "gzip, identity");
  }

  SECTION("malformed gzip (bad magic) -> 400 (task-1.3)")
  {
    auto r = http.post(url, "this is definitely not a gzip stream",
                       {{"Content-Type", "application/json"},
                        {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 400);
  }

  SECTION("truncated-but-valid-header gzip -> 400 (task-1.3, MALFORMED_INPUT)")
  {
    // A valid gzip stream with its tail dropped exercises the mid-stream EOF codec
    // path (distinct from bad-magic), which must also map to 400 (web F2).
    std::string truncated = gz(reqJson);
    REQUIRE(truncated.size() > 8);
    truncated.resize(truncated.size() - 5); // drop trailer/CRC bytes
    auto r = http.post(url, truncated, {{"Content-Type", "application/json"},
                                        {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 400);
  }

  SECTION("zip-bomb exceeding the decoded cap -> 413 (task-1.3)")
  {
    // 2 MiB of 'a' compresses to a few KB (< the 1 MiB compressed pre-filter), and
    // inflates past the 1 MiB _maxRequestBytes decoded cap -> OUTPUT_TOO_LARGE.
    const std::string bomb = gz(std::string(2 * 1024 * 1024, 'a'));
    REQUIRE(bomb.size() < 1024u * 1024u); // passes the compressed-input pre-filter
    auto r = http.post(url, bomb, {{"Content-Type", "application/json"},
                                   {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 413);
  }

  SECTION("media-type 415 carries NO Accept-Encoding (disambiguation, task-1.2)")
  {
    auto r = http.post(url, reqJson, {{"Content-Type", "text/plain"}}, 0);
    REQUIRE(r.statusCode == 415);
    REQUIRE(r.headers.count("Accept-Encoding") == 0);
  }

  SECTION("CORS: Access-Control-Allow-Headers lists Content-Encoding (task-1.5)")
  {
    // The header is set unconditionally at the top of handlePost (same value on
    // the OPTIONS preflight path), so a normal 200 response carries it too.
    auto r = http.post(url, reqJson, {{"Content-Type", "application/json"}}, 0);
    REQUIRE(r.statusCode == 200);
    auto it = r.headers.find("Access-Control-Allow-Headers");
    REQUIRE(it != r.headers.end());
    REQUIRE(it->second.find("Content-Encoding") != std::string::npos);
  }

  SECTION("CORS: OPTIONS preflight is auto-answered by the framework, 204 + Allow (task-1.5)")
  {
    // DISCOVERY while adding this case (cpp17 L2): the HttpServer AUTO_OPTIONS path
    // answers a preflight with 204 + Allow and does NOT invoke the plugin, so the
    // plugin's Access-Control-Allow-Headers (Content-Encoding included) never
    // reaches an OPTIONS preflight response. DP-10's browser-preflight goal is thus
    // UNMET — a pre-existing, cross-cutting CORS gap affecting ALL the plugin's
    // Access-Control-* headers, not just this slice's addition. Tracked in backlog
    // 2026-09-04-7 (needs its own review touching framework OPTIONS handling /
    // plugin CORS registration). The POST-response CORS header IS set (prior
    // SECTION); same-origin callers and simple (non-preflighted) requests are
    // unaffected. This case pins the ACTUAL behavior so a future fix is visible.
    const std::string reqBytes = "OPTIONS /rpc HTTP/1.1\r\n"
                                 "Host: localhost:8139\r\n"
                                 "Access-Control-Request-Method: POST\r\n"
                                 "Access-Control-Request-Headers: content-encoding\r\n"
                                 "Content-Length: 0\r\n"
                                 "Connection: close\r\n\r\n";
    const std::string resp = rawHttpRequest(8139, reqBytes);
    REQUIRE(resp.find("HTTP/1.1 204") != std::string::npos);
    REQUIRE(resp.find("Allow: POST, OPTIONS") != std::string::npos);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// SERVER decode DISABLED — enableRequestDecompression=false (task-1.2 / task-3.3).
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request server: decode disabled -> 415 with identity",
          "[gzip-request][server]")
{
  iora::IoraService &svc = startServer(8140, /*decode=*/false, /*auth=*/false);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  iora::network::HttpClient http;
  const std::string url = "http://localhost:8140/rpc";
  const std::string reqJson = kReqJson;

  SECTION("gzip request + decode off -> 415 with Accept-Encoding: identity (DP-7)")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 415);
    auto it = r.headers.find("Accept-Encoding");
    REQUIRE(it != r.headers.end());
    REQUIRE(it->second == "identity");
  }

  SECTION("identity-only + decode off -> 200 routed, NOT 415 (task-1.2)")
  {
    auto r = http.post(url, reqJson, {{"Content-Type", "application/json"},
                                      {"Content-Encoding", "identity"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// SERVER inflate-after-auth — requireAuth=true (task-1.4 DoS hardening).
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request server: unauthenticated compressed request is 401'd before decompression",
          "[gzip-request][server]")
{
  iora::IoraService &svc = startServer(8141, /*decode=*/true, /*auth=*/true);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  iora::network::HttpClient http;
  const std::string url = "http://localhost:8141/rpc";

  SECTION("no credentials + Content-Encoding: gzip -> 401 (not 415)")
  {
    auto r = http.post(url, gz(std::string(kReqJson)),
                       {{"Content-Type", "application/json"},
                        {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 401);
  }

  SECTION("a zip-bomb behind a 401 yields 401, never 413 (no inflate ran)")
  {
    const std::string bomb = gz(std::string(2 * 1024 * 1024, 'a'));
    auto r = http.post(url, bomb, {{"Content-Type", "application/json"},
                                   {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 401); // decompression never reached
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// CLIENT compression + 415 safety-net (task-2.x, task-3.2). Against /capture.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request client: compress decision on the wire", "[gzip-request][client]")
{
  iora::IoraService &svc = startCaptureService(8142);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::string ep = "http://localhost:8142/capture";
  auto params = iora::parsers::Json::object();
  params["payload"] = std::string(200, 'z'); // safely over any small threshold

  SECTION("enabled + over threshold -> request carries Content-Encoding: gzip (task-2.1)")
  {
    JsonRpcClient client(svc, pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));
    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object()); // round-trip returned the capture's result

    std::lock_guard<std::mutex> lk(g_cap.m);
    REQUIRE(g_cap.count == 1);
    REQUIRE(g_cap.ce[0] == "gzip");
    REQUIRE(g_cap.ct[0].find("application/json") != std::string::npos);
    // The body is genuinely compressed and inflates back to the JSON envelope.
    auto decoded = iora::util::Gzip::decompress(g_cap.body[0], 1024 * 1024);
    REQUIRE(decoded.isOk());
    REQUIRE(decoded.value().find("\"method\":\"echo\"") != std::string::npos);
    REQUIRE(decoded.value().find("payload") != std::string::npos);
    REQUIRE(g_cap.body[0] != decoded.value()); // compressed != plaintext
  }

  SECTION("enabled + sub-threshold -> identity (no Content-Encoding) (task-2.1 threshold)")
  {
    JsonRpcClient client(svc, pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/1 << 20));
    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object());

    std::lock_guard<std::mutex> lk(g_cap.m);
    REQUIRE(g_cap.count == 1);
    REQUIRE(g_cap.ce[0].empty());
    REQUIRE(g_cap.body[0].find("\"method\":\"echo\"") != std::string::npos); // plaintext JSON
  }

  SECTION("disabled -> identity even for a large body (task-2.1)")
  {
    JsonRpcClient client(svc, pool, clientCompressionConfig(/*enable=*/false, /*threshold=*/32));
    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object());

    std::lock_guard<std::mutex> lk(g_cap.m);
    REQUIRE(g_cap.count == 1);
    REQUIRE(g_cap.ce[0].empty());
  }

  SECTION("a CALLER-supplied Content-Encoding is still rejected (DP-8)")
  {
    JsonRpcClient client(svc, pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));
    std::vector<std::pair<std::string, std::string>> headers{{"Content-Encoding", "gzip"}};
    REQUIRE_THROWS_AS(client.call(ep, "echo", params, headers), JsonRpcError);
    std::lock_guard<std::mutex> lk(g_cap.m);
    REQUIRE(g_cap.count == 0); // rejected before anything reached the wire
  }
}

TEST_CASE("gzip request client: 415 safety-net latches off and retries identity",
          "[gzip-request][client]")
{
  iora::IoraService &svc = startCaptureService(8143);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::string ep = "http://localhost:8143/capture";
  const std::string origin = iora::network::normalizeOrigin(ep);
  auto params = iora::parsers::Json::object();
  params["payload"] = std::string(200, 'z');

  auto set415CompressedPolicy = [](bool withAcceptEncoding)
  {
    std::lock_guard<std::mutex> lk(g_cap.m);
    g_cap.policy = [withAcceptEncoding](int, bool compressed,
                                        iora::network::WebhookServer::Response &res)
    {
      if (compressed)
      {
        if (withAcceptEncoding)
        {
          res.set_header("Accept-Encoding", "identity");
        }
        res.status = 415;
        res.set_content(kUnsupportedCodingBody, "application/json");
      }
      else
      {
        res.status = 200;
        res.set_content(kOkResult, "application/json");
      }
    };
  };

  SECTION("415 WITH Accept-Encoding -> identity retry succeeds + latch (task-2.3)")
  {
    set415CompressedPolicy(/*withAcceptEncoding=*/true);
    JsonRpcClient client(svc, pool, clientCompressionConfig(true, 32));

    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object()); // succeeded via the identity retry

    {
      std::lock_guard<std::mutex> lk(g_cap.m);
      REQUIRE(g_cap.count == 2);
      REQUIRE(g_cap.ce[0] == "gzip");  // first attempt compressed
      REQUIRE(g_cap.ce[1].empty());    // identity re-entry
    }
    REQUIRE(JsonRpcClientTestAccess::isRequestOriginLatchedOff(client, origin));

    // A subsequent call stays identity (latched off) — no second 415 round-trip.
    auto result2 = client.call(ep, "echo", params);
    REQUIRE(result2.is_object());
    std::lock_guard<std::mutex> lk(g_cap.m);
    REQUIRE(g_cap.count == 3);
    REQUIRE(g_cap.ce[2].empty()); // identity directly
  }

  SECTION("415 WITHOUT Accept-Encoding still triggers the identity retry (DP-3)")
  {
    set415CompressedPolicy(/*withAcceptEncoding=*/false);
    JsonRpcClient client(svc, pool, clientCompressionConfig(true, 32));

    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object());
    std::lock_guard<std::mutex> lk(g_cap.m);
    REQUIRE(g_cap.count == 2);
    REQUIRE(g_cap.ce[0] == "gzip");
    REQUIRE(g_cap.ce[1].empty());
  }

  SECTION("identity retry bounded ONCE: a 2nd 415 propagates, no further retry (cpp17 M5)")
  {
    // Always 415, even for identity: the identity re-entry's 415 is a genuine
    // failure (sendJson_ does not raise ContentCodingRejectedError on an
    // uncompressed request), so the wrapper does not loop again.
    {
      std::lock_guard<std::mutex> lk(g_cap.m);
      g_cap.policy = [](int, bool, iora::network::WebhookServer::Response &res)
      {
        res.status = 415;
        res.set_content(kUnsupportedCodingBody, "application/json");
      };
    }
    JsonRpcClient client(svc, pool, clientCompressionConfig(true, 32));

    REQUIRE_THROWS(client.call(ep, "echo", params));
    std::lock_guard<std::mutex> lk(g_cap.m);
    REQUIRE(g_cap.count == 2); // compressed 415 + one identity 415, then stop
  }

  SECTION("TTL re-probe: after a forced expiry the origin compresses again (task-2.4)")
  {
    set415CompressedPolicy(/*withAcceptEncoding=*/true);
    JsonRpcClient client(svc, pool, clientCompressionConfig(true, 32));

    // First call latches off (compress -> 415 -> identity).
    REQUIRE(client.call(ep, "echo", params).is_object());
    REQUIRE(JsonRpcClientTestAccess::isRequestOriginLatchedOff(client, origin));
    int countAfterFirst = 0;
    {
      std::lock_guard<std::mutex> lk(g_cap.m);
      countAfterFirst = g_cap.count; // 2
    }

    // Force the re-probe boundary into the past; the next call must compress again.
    JsonRpcClientTestAccess::expireRequestCompressionTtl(client, origin);
    REQUIRE(client.call(ep, "echo", params).is_object());

    std::lock_guard<std::mutex> lk(g_cap.m);
    REQUIRE(g_cap.count == countAfterFirst + 2); // re-probe compressed + identity retry
    REQUIRE(g_cap.ce[countAfterFirst] == "gzip"); // re-probe attempt was compressed
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// End-to-end: the CLIENT compresses and the REAL server decodes, in ONE flow
// (cpp17 M3). Closes the seam that the /capture (client) and raw-HttpClient
// (server) suites each exercise only one half of.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request: client compresses, the REAL server decodes (round-trip)",
          "[gzip-request][roundtrip]")
{
  const std::string big(300, 'q');

  SECTION("decode-enabled server: a compressed request round-trips")
  {
    iora::IoraService &svc = startServer(8144, /*decode=*/true, /*auth=*/false);
    iora::IoraService::AutoServiceShutdown autoShutdown(svc);
    iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
    JsonRpcClient client(svc, pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));

    auto params = iora::parsers::Json::object();
    params["payload"] = big;
    auto result = client.call("http://localhost:8144/rpc", "echo", params);
    REQUIRE(result.is_object());
    REQUIRE(result["payload"].get<std::string>() == big); // echoed by the real server
  }

  SECTION("decode-disabled server: client 415s, latches, retries identity, succeeds")
  {
    iora::IoraService &svc = startServer(8145, /*decode=*/false, /*auth=*/false);
    iora::IoraService::AutoServiceShutdown autoShutdown(svc);
    iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
    JsonRpcClient client(svc, pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));

    const std::string ep = "http://localhost:8145/rpc";
    auto params = iora::parsers::Json::object();
    params["payload"] = big;
    // Against the REAL server (not /capture): compress -> real 415-with-Accept-
    // Encoding -> typed carrier -> latch -> identity retry -> real 200.
    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object());
    REQUIRE(result["payload"].get<std::string>() == big);
    REQUIRE(JsonRpcClientTestAccess::isRequestOriginLatchedOff(
      client, iora::network::normalizeOrigin(ep)));
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// Concurrency: the per-origin request-compression cache (thread-safety finding).
// Hammers the two synchronized access sites + the TTL reset from many threads on
// a SHARED origin (read/write on one key) AND per-thread DISTINCT origins
// (concurrent insert-if-absent / rehash). Runs clean here; under a TSan build
// (-DIORA_ENABLE_TSAN=ON) removing the leaf mutex trips a data race.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request: request-compression cache is concurrency-safe",
          "[gzip-request][concurrency]")
{
  iora::IoraService &svc = startCaptureService(8146);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  JsonRpcClient client(svc, pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));

  constexpr int kThreads = 8;
  constexpr int kIters = 1000;
  std::atomic<bool> go{false};
  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; ++t)
  {
    threads.emplace_back(
      [&, t]
      {
        while (!go.load(std::memory_order_acquire))
        {
          std::this_thread::yield();
        }
        const std::string shared = "http://shared:9";
        const std::string mine = "http://origin-" + std::to_string(t) + ":9";
        for (int i = 0; i < kIters; ++i)
        {
          (void)JsonRpcClientTestAccess::callShouldCompress(client, shared);
          (void)JsonRpcClientTestAccess::callShouldCompress(client, mine);
          if ((i & 1) == 0)
          {
            JsonRpcClientTestAccess::callLatchOff(client, shared);
          }
          if ((i % 7) == 0)
          {
            JsonRpcClientTestAccess::expireRequestCompressionTtl(client, shared);
          }
        }
      });
  }
  go.store(true, std::memory_order_release);
  for (auto &th : threads)
  {
    th.join();
  }
  SUCCEED("cache access is serialized (clean under TSan with the leaf mutex)");
}
