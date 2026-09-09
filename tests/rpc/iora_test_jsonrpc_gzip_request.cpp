// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// PORTED (tracker 2026-07-26-1 task-6.7, C1) from
// src/modules/connectors/jsonrpc_client/tests/iora_test_jsonrpc_gzip_request.cpp.
// The SERVER side no longer loads the DELETED mod_jsonrpc_server.so plugin via
// IoraService: it is REWRITTEN to compose iora::network::HttpServer +
// iora::rpc::JsonRpcServer + iora::rpc::JsonRpcHttpEndpoint on an ephemeral port
// (the same composition task-8.1 uses). The /capture client-side counterparty is
// a raw HttpServer onPost handler (no webhookServer). The migrated client
// enforces id-correlation (task-5b.3), so the capture ECHOES the request id.
// Namespace iora::modules::connectors -> iora::rpc; JsonRpcClient drops the
// leading IoraService&. The JsonRpcClientTestAccess seam moves into namespace
// iora::rpc (the moved header friends ::iora::rpc::JsonRpcClientTestAccess).
//
// DROPPED (migration deliberately ships NO CORS — task-3.5 / task-4.2; CORS is
// tracker A): the old "CORS: Access-Control-Allow-Headers lists Content-Encoding"
// POST case is removed — the migrated endpoint emits no Access-Control-* header.
// The OPTIONS-preflight case is KEPT: it asserts the framework AUTO_OPTIONS 204 +
// Allow, which the composed HttpServer still provides (unrelated to plugin CORS).
//
// Request-direction tests for the JSON-RPC bidirectional negotiated-gzip Consumer
// C (arch architecture/iora/jsonrpc_gzip_compression.json): the CLIENT compresses
// request bodies (config-driven, over threshold) and the SERVER decodes them, with
// the 415 safety-net (single latch-off + TTL re-probe).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/rpc/jsonrpc_client.hpp" // JsonRpcClient, Config, ContentCodingRejectedError

#include "jsonrpc_test_support.hpp" // testrpc::ComposedRpcServer, requestId; brings jsonrpc_http/server

#include "iora/core/thread_pool.hpp"
#include "iora/network/http_client.hpp"
#include "iora/network/http_server.hpp"
#include "iora/parsers/http_message.hpp" // normalizeOrigin
#include "iora/util/gzip.hpp"

#include "iora_test_net_utils.hpp" // testnet::getFreePortTCP

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using iora::parsers::Json;
using iora::rpc::Config;
using iora::rpc::JsonRpcClient;
using iora::rpc::JsonRpcError;
using namespace std::chrono_literals;

// ─────────────────────────────────────────────────────────────────────────────
// Test-access seam: reach the per-origin request-compression cache to force-expire
// a latch's TTL (deterministic re-probe test) and observe latch state. Defined in
// the befriended namespace iora::rpc so it can reach JsonRpcClient::_impl and
// Impl's private _requestCompressionState / _requestCompressionMutex.
// ─────────────────────────────────────────────────────────────────────────────
namespace iora
{
namespace rpc
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
} // namespace rpc
} // namespace iora

namespace
{

using JsonHandler = std::function<Json(const Json &)>;

std::string gz(const std::string &s) { return iora::util::Gzip::compress(s); }

const char *const kReqJson =
  R"({"jsonrpc":"2.0","method":"echo","params":{"x":"hello-world"},"id":1})";
const char *const kUnsupportedCodingBody =
  R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"Unsupported Content-Encoding"},"id":null})";

// The wire-level server is the shared testrpc::ComposedRpcServer (Slice-B review
// L8: HttpServer + JsonRpcServer + JsonRpcHttpEndpoint, D-LIFETIME ordering encoded
// once). This suite exercises the request-decode + auth-before-decode knobs; the
// default "echo" method (returns its params) round-trips "hello-world". requireAuth
// with no tokenValidator FAILS CLOSED (401), which is the "401 before decompression"
// behaviour under test — the endpoint decides auth BEFORE any content-coding inspect.
testrpc::ComposedRpcServerOptions serverOpts(bool decode, bool auth)
{
  testrpc::ComposedRpcServerOptions o;
  o.enableRequestDecompression = decode;
  o.requireAuth = auth;
  return o;
}

// ── /capture counterparty: a raw HttpServer that records the wire request and
//    replies per an installable policy. Replaces the plugin webhookServer. Because
//    the migrated client enforces id-correlation (task-5b.3), every 2xx success
//    reply ECHOES the request id (inflating the body first when gzip-encoded).
class CaptureServer
{
public:
  struct State
  {
    std::mutex m;
    int count = 0;
    std::vector<std::string> ce;   // Content-Encoding per request ("" if absent)
    std::vector<std::string> ct;   // Content-Type per request
    std::vector<std::string> body; // raw (possibly compressed) body per request
    // policy(idx, compressed, reqId, res): decide the reply. Default: 200 + ok echoing id.
    std::function<void(int, bool, const Json &, iora::network::HttpServer::Response &)> policy;
  };

  CaptureServer() : _port(testnet::getFreePortTCP()), _http("127.0.0.1", static_cast<int>(_port))
  {
    _http.onPost("/capture",
                 [this](const iora::network::HttpServer::Request &req,
                        iora::network::HttpServer::Response &res)
                 {
                   std::function<void(int, bool, const Json &, iora::network::HttpServer::Response &)>
                     policy;
                   int idx;
                   bool compressed;
                   Json reqId(nullptr);
                   {
                     std::lock_guard<std::mutex> lk(_state.m);
                     idx = _state.count++;
                     const std::string ceVal =
                       req.has_header("Content-Encoding") ? req.get_header_value("Content-Encoding") : "";
                     _state.ce.push_back(ceVal);
                     _state.ct.push_back(req.has_header("Content-Type")
                                           ? req.get_header_value("Content-Type")
                                           : "");
                     _state.body.push_back(req.body);
                     compressed = !ceVal.empty();
                     reqId = testrpc::requestIdInflating(req.body, compressed);
                     policy = _state.policy; // copy-then-invoke: never hold the lock across the handler
                   }
                   if (policy)
                   {
                     policy(idx, compressed, reqId, res);
                   }
                   else
                   {
                     res.status = 200;
                     res.set_content(okResultForId(reqId), "application/json");
                   }
                 });
    _http.start();
    std::this_thread::sleep_for(200ms);
  }
  ~CaptureServer() { _http.stop(); }

  CaptureServer(const CaptureServer &) = delete;
  CaptureServer &operator=(const CaptureServer &) = delete;

  std::string url() const { return "http://localhost:" + std::to_string(_port) + "/capture"; }
  State &state() { return _state; }

  /// A JSON-RPC success envelope {"result":{"ok":true}} echoing \p id.
  static std::string okResultForId(const Json &id)
  {
    Json env;
    env["jsonrpc"] = "2.0";
    Json result = Json::object();
    result["ok"] = true;
    env["result"] = result;
    env["id"] = id;
    return env.dump();
  }

private:
  // Slice-B review L9/S-3: id extraction is the shared testrpc::requestIdInflating,
  // called directly at the handler (no single-caller forwarder); this fixture keeps
  // only its own envelope builder (okResultForId).
  std::uint16_t _port;
  iora::network::HttpServer _http;
  State _state;
};

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
// SERVER decode — enableRequestDecompression=true, requireAuth=false. Driven with
// a raw HttpClient against the composed /rpc endpoint.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request server: decode enabled round-trip + list handling",
          "[gzip-request][server]")
{
  testrpc::ComposedRpcServer server(serverOpts(/*decode=*/true, /*auth=*/false));
  iora::network::HttpClient http;
  const std::string url = server.url();
  const std::string reqJson = kReqJson;

  SECTION("gzip request decodes and routes")
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

  SECTION("stacked 'gzip, gzip' double-decodes")
  {
    auto r = http.post(url, gz(gz(reqJson)),
                       {{"Content-Type", "application/json"},
                        {"Content-Encoding", "gzip, gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("two physical Content-Encoding lines combine (§5.3) then double-decode")
  {
    // End-to-end composition of the §5.3 combine (two Content-Encoding field-lines
    // -> "gzip, gzip") with decode. HttpClient's map API cannot emit duplicate
    // header lines, so drive it over the raw socket. Body is double-gzipped.
    const std::string doubled = gz(gz(reqJson));
    const std::string reqBytes = "POST /rpc HTTP/1.1\r\n"
                                 "Host: localhost:" +
                                 std::to_string(server.port()) +
                                 "\r\n"
                                 "Content-Type: application/json\r\n"
                                 "Content-Encoding: gzip\r\n"
                                 "Content-Encoding: gzip\r\n"
                                 "Content-Length: " +
                                 std::to_string(doubled.size()) +
                                 "\r\n"
                                 "Connection: close\r\n\r\n" +
                                 doubled;
    const std::string resp = testnet::rawHttpRequest(server.port(), reqBytes);
    REQUIRE(resp.find("HTTP/1.1 200") != std::string::npos);
    REQUIRE(resp.find("hello-world") != std::string::npos);
  }

  SECTION("'identity, gzip' decodes (identity is a no-op)")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "identity, gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("empty list elements are skipped 'gzip,,' (§5.6.1)")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "gzip,,"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("'x-gzip' is a decode-side alias of gzip (§8.4.1)")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "x-gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("coding token is ASCII case-insensitive 'GZIP'")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "GZIP"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("identity-only decodable even with a coding present")
  {
    auto r = http.post(url, reqJson, {{"Content-Type", "application/json"},
                                      {"Content-Encoding", "identity"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }

  SECTION("unknown coding -> 415 whose Accept-Encoding lists gzip AND identity")
  {
    auto r = http.post(url, reqJson, {{"Content-Type", "application/json"},
                                      {"Content-Encoding", "br"}}, 0);
    REQUIRE(r.statusCode == 415);
    auto it = r.headers.find("Accept-Encoding");
    REQUIRE(it != r.headers.end());
    REQUIRE(it->second == "gzip, identity");
  }

  SECTION(">2 stacked codings -> 415 (not 500), still with Accept-Encoding")
  {
    auto r = http.post(url, gz(gz(gz(reqJson))),
                       {{"Content-Type", "application/json"},
                        {"Content-Encoding", "gzip, gzip, gzip"}}, 0);
    REQUIRE(r.statusCode == 415);
    // Every undecodable 415 — including the over-cap branch — carries the
    // Accept-Encoding decodable set, else the client latch-off would not fire.
    auto it = r.headers.find("Accept-Encoding");
    REQUIRE(it != r.headers.end());
    REQUIRE(it->second == "gzip, identity");
  }

  SECTION("malformed gzip (bad magic) -> 400")
  {
    auto r = http.post(url, "this is definitely not a gzip stream",
                       {{"Content-Type", "application/json"},
                        {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 400);
  }

  SECTION("truncated-but-valid-header gzip -> 400 (MALFORMED_INPUT)")
  {
    std::string truncated = gz(reqJson);
    REQUIRE(truncated.size() > 8);
    truncated.resize(truncated.size() - 5); // drop trailer/CRC bytes
    auto r = http.post(url, truncated, {{"Content-Type", "application/json"},
                                        {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 400);
  }

  SECTION("zip-bomb exceeding the decoded cap -> 413")
  {
    // 2 MiB of 'a' compresses to a few KB (< the 1 MiB compressed pre-filter) and
    // inflates past the 1 MiB maxRequestBytes decoded cap -> OUTPUT_TOO_LARGE.
    const std::string bomb = gz(std::string(2 * 1024 * 1024, 'a'));
    REQUIRE(bomb.size() < 1024u * 1024u); // passes the compressed-input pre-filter
    auto r = http.post(url, bomb, {{"Content-Type", "application/json"},
                                   {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 413);
  }

  SECTION("media-type 415 carries NO Accept-Encoding (disambiguation)")
  {
    auto r = http.post(url, reqJson, {{"Content-Type", "text/plain"}}, 0);
    REQUIRE(r.statusCode == 415);
    REQUIRE(r.headers.count("Accept-Encoding") == 0);
  }

  SECTION("OPTIONS preflight is auto-answered by the framework, 204 + Allow")
  {
    // The composed HttpServer's AUTO_OPTIONS path answers a preflight with 204 +
    // Allow without invoking the endpoint handler (unchanged framework behaviour;
    // the migration ships no CORS of its own — task-3.5). This pins the actual
    // framework response.
    const std::string reqBytes = "OPTIONS /rpc HTTP/1.1\r\n"
                                 "Host: localhost:" +
                                 std::to_string(server.port()) +
                                 "\r\n"
                                 "Access-Control-Request-Method: POST\r\n"
                                 "Access-Control-Request-Headers: content-encoding\r\n"
                                 "Content-Length: 0\r\n"
                                 "Connection: close\r\n\r\n";
    const std::string resp = testnet::rawHttpRequest(server.port(), reqBytes);
    REQUIRE(resp.find("HTTP/1.1 204") != std::string::npos);
    REQUIRE(resp.find("Allow: POST, OPTIONS") != std::string::npos);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// SERVER decode DISABLED — enableRequestDecompression=false.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request server: decode disabled -> 415 with identity",
          "[gzip-request][server]")
{
  testrpc::ComposedRpcServer server(serverOpts(/*decode=*/false, /*auth=*/false));
  iora::network::HttpClient http;
  const std::string url = server.url();
  const std::string reqJson = kReqJson;

  SECTION("gzip request + decode off -> 415 with Accept-Encoding: identity")
  {
    auto r = http.post(url, gz(reqJson), {{"Content-Type", "application/json"},
                                          {"Content-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 415);
    auto it = r.headers.find("Accept-Encoding");
    REQUIRE(it != r.headers.end());
    REQUIRE(it->second == "identity");
  }

  SECTION("identity-only + decode off -> 200 routed, NOT 415")
  {
    auto r = http.post(url, reqJson, {{"Content-Type", "application/json"},
                                      {"Content-Encoding", "identity"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.body.find("hello-world") != std::string::npos);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// SERVER inflate-after-auth — requireAuth=true (DoS hardening: auth precedes decode).
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request server: unauthenticated compressed request is 401'd before decompression",
          "[gzip-request][server]")
{
  testrpc::ComposedRpcServer server(serverOpts(/*decode=*/true, /*auth=*/true));
  iora::network::HttpClient http;
  const std::string url = server.url();

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
// CLIENT compression + 415 safety-net. Against /capture.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request client: compress decision on the wire", "[gzip-request][client]")
{
  CaptureServer server;
  auto &cap = server.state();
  iora::core::ThreadPool pool(2, 2, 1s);
  const std::string ep = server.url();
  auto params = Json::object();
  params["payload"] = std::string(200, 'z'); // safely over any small threshold

  SECTION("enabled + over threshold -> request carries Content-Encoding: gzip")
  {
    JsonRpcClient client(pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));
    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object()); // round-trip returned the capture's result

    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.count == 1);
    REQUIRE(cap.ce[0] == "gzip");
    REQUIRE(cap.ct[0].find("application/json") != std::string::npos);
    // The body is genuinely compressed and inflates back to the JSON envelope.
    auto decoded = iora::util::Gzip::decompress(cap.body[0], 1024 * 1024);
    REQUIRE(decoded.isOk());
    REQUIRE(decoded.value().find("\"method\":\"echo\"") != std::string::npos);
    REQUIRE(decoded.value().find("payload") != std::string::npos);
    REQUIRE(cap.body[0] != decoded.value()); // compressed != plaintext
  }

  SECTION("enabled + sub-threshold -> identity (no Content-Encoding)")
  {
    JsonRpcClient client(pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/1 << 20));
    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object());

    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.count == 1);
    REQUIRE(cap.ce[0].empty());
    REQUIRE(cap.body[0].find("\"method\":\"echo\"") != std::string::npos); // plaintext JSON
  }

  SECTION("disabled -> identity even for a large body")
  {
    JsonRpcClient client(pool, clientCompressionConfig(/*enable=*/false, /*threshold=*/32));
    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object());

    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.count == 1);
    REQUIRE(cap.ce[0].empty());
  }

  SECTION("a CALLER-supplied Content-Encoding is still rejected (DP-8)")
  {
    JsonRpcClient client(pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));
    std::vector<std::pair<std::string, std::string>> headers{{"Content-Encoding", "gzip"}};
    REQUIRE_THROWS_AS(client.call(ep, "echo", params, headers), JsonRpcError);
    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.count == 0); // rejected before anything reached the wire
  }
}

TEST_CASE("gzip request client: 415 safety-net latches off and retries identity",
          "[gzip-request][client]")
{
  CaptureServer server;
  auto &cap = server.state();
  iora::core::ThreadPool pool(2, 2, 1s);
  const std::string ep = server.url();
  const std::string origin = iora::network::normalizeOrigin(ep);
  auto params = Json::object();
  params["payload"] = std::string(200, 'z');

  auto set415CompressedPolicy = [&cap](bool withAcceptEncoding)
  {
    std::lock_guard<std::mutex> lk(cap.m);
    cap.policy = [withAcceptEncoding](int, bool compressed, const Json &reqId,
                                      iora::network::HttpServer::Response &res)
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
        res.set_content(CaptureServer::okResultForId(reqId), "application/json");
      }
    };
  };

  SECTION("415 WITH Accept-Encoding -> identity retry succeeds + latch")
  {
    set415CompressedPolicy(/*withAcceptEncoding=*/true);
    JsonRpcClient client(pool, clientCompressionConfig(true, 32));

    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object()); // succeeded via the identity retry

    {
      std::lock_guard<std::mutex> lk(cap.m);
      REQUIRE(cap.count == 2);
      REQUIRE(cap.ce[0] == "gzip"); // first attempt compressed
      REQUIRE(cap.ce[1].empty());   // identity re-entry
    }
    REQUIRE(iora::rpc::JsonRpcClientTestAccess::isRequestOriginLatchedOff(client, origin));

    // A subsequent call stays identity (latched off) — no second 415 round-trip.
    auto result2 = client.call(ep, "echo", params);
    REQUIRE(result2.is_object());
    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.count == 3);
    REQUIRE(cap.ce[2].empty()); // identity directly
  }

  SECTION("415 WITHOUT Accept-Encoding still triggers the identity retry (DP-3)")
  {
    set415CompressedPolicy(/*withAcceptEncoding=*/false);
    JsonRpcClient client(pool, clientCompressionConfig(true, 32));

    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object());
    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.count == 2);
    REQUIRE(cap.ce[0] == "gzip");
    REQUIRE(cap.ce[1].empty());
  }

  SECTION("identity retry bounded ONCE: a 2nd 415 propagates, no further retry")
  {
    // Always 415, even for identity: the identity re-entry's 415 is a genuine
    // failure (sendJson_ does not raise ContentCodingRejectedError on an
    // uncompressed request), so the wrapper does not loop again.
    {
      std::lock_guard<std::mutex> lk(cap.m);
      cap.policy = [](int, bool, const Json &, iora::network::HttpServer::Response &res)
      {
        res.status = 415;
        res.set_content(kUnsupportedCodingBody, "application/json");
      };
    }
    JsonRpcClient client(pool, clientCompressionConfig(true, 32));

    REQUIRE_THROWS(client.call(ep, "echo", params));
    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.count == 2); // compressed 415 + one identity 415, then stop
  }

  SECTION("TTL re-probe: after a forced expiry the origin compresses again")
  {
    set415CompressedPolicy(/*withAcceptEncoding=*/true);
    JsonRpcClient client(pool, clientCompressionConfig(true, 32));

    // First call latches off (compress -> 415 -> identity).
    REQUIRE(client.call(ep, "echo", params).is_object());
    REQUIRE(iora::rpc::JsonRpcClientTestAccess::isRequestOriginLatchedOff(client, origin));
    int countAfterFirst = 0;
    {
      std::lock_guard<std::mutex> lk(cap.m);
      countAfterFirst = cap.count; // 2
    }

    // Force the re-probe boundary into the past; the next call must compress again.
    iora::rpc::JsonRpcClientTestAccess::expireRequestCompressionTtl(client, origin);
    REQUIRE(client.call(ep, "echo", params).is_object());

    std::lock_guard<std::mutex> lk(cap.m);
    REQUIRE(cap.count == countAfterFirst + 2); // re-probe compressed + identity retry
    REQUIRE(cap.ce[countAfterFirst] == "gzip"); // re-probe attempt was compressed
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// End-to-end: the CLIENT compresses and the REAL server decodes, in ONE flow.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request: client compresses, the REAL server decodes (round-trip)",
          "[gzip-request][roundtrip]")
{
  const std::string big(300, 'q');

  SECTION("decode-enabled server: a compressed request round-trips")
  {
    testrpc::ComposedRpcServer server(serverOpts(/*decode=*/true, /*auth=*/false));
    iora::core::ThreadPool pool(2, 2, 1s);
    JsonRpcClient client(pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));

    auto params = Json::object();
    params["payload"] = big;
    auto result = client.call(server.url(), "echo", params);
    REQUIRE(result.is_object());
    REQUIRE(result["payload"].get<std::string>() == big); // echoed by the real server
  }

  SECTION("decode-disabled server: client 415s, latches, retries identity, succeeds")
  {
    testrpc::ComposedRpcServer server(serverOpts(/*decode=*/false, /*auth=*/false));
    iora::core::ThreadPool pool(2, 2, 1s);
    JsonRpcClient client(pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));

    const std::string ep = server.url();
    auto params = Json::object();
    params["payload"] = big;
    // Against the REAL server: compress -> real 415-with-Accept-Encoding -> typed
    // carrier -> latch -> identity retry -> real 200.
    auto result = client.call(ep, "echo", params);
    REQUIRE(result.is_object());
    REQUIRE(result["payload"].get<std::string>() == big);
    REQUIRE(iora::rpc::JsonRpcClientTestAccess::isRequestOriginLatchedOff(
      client, iora::network::normalizeOrigin(ep)));
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// Concurrency: the per-origin request-compression cache. Hammers the two
// synchronized access sites + the TTL reset from many threads on a SHARED origin
// (read/write on one key) AND per-thread DISTINCT origins (insert-if-absent /
// rehash). Runs clean here; under a TSan build (-DIORA_ENABLE_TSAN=ON) removing
// the leaf _requestCompressionMutex trips a data race. SOLE owner of the ported
// _requestCompressionMutex probe (B-cpp L-1).
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip request: request-compression cache is concurrency-safe",
          "[gzip-request][concurrency]")
{
  iora::core::ThreadPool pool(2, 2, 1s);
  JsonRpcClient client(pool, clientCompressionConfig(/*enable=*/true, /*threshold=*/32));

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
          (void)iora::rpc::JsonRpcClientTestAccess::callShouldCompress(client, shared);
          (void)iora::rpc::JsonRpcClientTestAccess::callShouldCompress(client, mine);
          if ((i & 1) == 0)
          {
            iora::rpc::JsonRpcClientTestAccess::callLatchOff(client, shared);
          }
          if ((i % 7) == 0)
          {
            iora::rpc::JsonRpcClientTestAccess::expireRequestCompressionTtl(client, shared);
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
