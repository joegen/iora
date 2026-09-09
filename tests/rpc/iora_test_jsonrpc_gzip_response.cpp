// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// PORTED (tracker 2026-07-26-1 task-6.7, C1) from
// src/modules/connectors/jsonrpc_client/tests/iora_test_jsonrpc_gzip_response.cpp.
// The SERVER side no longer loads the DELETED mod_jsonrpc_server.so plugin via
// IoraService: it is REWRITTEN to compose iora::network::HttpServer +
// iora::rpc::JsonRpcServer + iora::rpc::JsonRpcHttpEndpoint on an ephemeral port.
// The /capture client-side counterparty is a raw HttpServer onPost handler (no
// webhookServer); its crafted response bodies use id=1, which correlates because a
// fresh JsonRpcClient's first call is id=1 (task-5b.3). Namespace
// iora::modules::connectors -> iora::rpc; JsonRpcClient drops the leading
// IoraService&.
//
// Response-direction tests for the JSON-RPC bidirectional negotiated-gzip Consumer
// C: the SERVER compresses response bodies when Accept-Encoding negotiates gzip
// (Content-Encoding + Vary), the CLIENT decodes them, plus the client cap-alignment
// and response-bomb guard.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/rpc/jsonrpc_client.hpp"

#include "jsonrpc_test_support.hpp" // testrpc::ComposedRpcServer; brings jsonrpc_http/server + net_utils

#include "iora/core/string_utils.hpp"
#include "iora/core/thread_pool.hpp"
#include "iora/network/http_client.hpp"
#include "iora/network/http_server.hpp"
#include "iora/util/gzip.hpp"

#include "iora_test_net_utils.hpp" // testnet::getFreePortTCP

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using iora::parsers::Json;
using iora::rpc::Config;
using iora::rpc::JsonRpcClient;
using iora::rpc::JsonRpcError;
using namespace std::chrono_literals;

namespace
{

std::string gz(const std::string &s) { return iora::util::Gzip::compress(s); }
std::string gunzip(const std::string &s, std::size_t cap = 64 * 1024 * 1024)
{
  auto r = iora::util::Gzip::decompress(s, cap);
  REQUIRE(r.isOk());
  return std::move(r).value();
}

const char *const kOkResult = R"({"jsonrpc":"2.0","result":{"ok":true},"id":1})";

// A JSON-RPC request calling `echo` with an inline string payload, so the server's
// echoed result envelope is a controllable size (drives the compression threshold).
std::string echoReq(const std::string &payload)
{
  return R"({"jsonrpc":"2.0","method":"echo","params":{"x":")" + payload + R"("},"id":1})";
}
// A JSON-RPC NOTIFICATION (no id) -> the router yields an empty response -> 204.
std::string echoNotify(const std::string &payload)
{
  return R"({"jsonrpc":"2.0","method":"echo","params":{"x":")" + payload + R"("}})";
}

// ── raw-response header inspection (raw REQUEST send is testnet::rawHttpRequest) ──
// First value of a header (case-insensitive name) in a raw HTTP response, trimmed;
// "" if absent. Only scans the header block (up to the CRLFCRLF).
std::string rawHeader(const std::string &resp, const std::string &name)
{
  const std::size_t hdrEnd = resp.find("\r\n\r\n");
  const std::string head = resp.substr(0, hdrEnd == std::string::npos ? resp.size() : hdrEnd);
  const std::string want = iora::core::StringUtils::toLower(name) + ":";
  std::size_t pos = head.find("\r\n"); // skip the status line
  while (pos != std::string::npos)
  {
    const std::size_t lineStart = pos + 2;
    const std::size_t lineEnd = head.find("\r\n", lineStart);
    const std::string line =
      head.substr(lineStart, lineEnd == std::string::npos ? std::string::npos : lineEnd - lineStart);
    if (iora::core::StringUtils::toLower(line).rfind(want, 0) == 0)
    {
      std::string v = line.substr(want.size());
      const std::size_t b = v.find_first_not_of(" \t");
      const std::size_t e = v.find_last_not_of(" \t");
      return b == std::string::npos ? "" : v.substr(b, e - b + 1);
    }
    pos = lineEnd;
  }
  return "";
}

// The wire-level server is the shared testrpc::ComposedRpcServer (Slice-B review
// L8). This suite registers `echo` (returns params) and `boom` (throws, so the
// router surfaces a JSON-RPC error envelope at 200) and drives the response-
// compression / Vary knobs.
testrpc::ComposedRpcServerOptions serverOpts(bool responseCompression, std::size_t threshold,
                                             bool auth = false, bool requestDecompression = false)
{
  testrpc::ComposedRpcServerOptions o;
  o.enableResponseCompression = responseCompression;
  o.enableRequestDecompression = requestDecompression;
  o.compressionThreshold = threshold;
  o.requireAuth = auth;
  o.registerMethods = [](iora::rpc::JsonRpcServer &s)
  {
    s.registerMethod("echo", [](const Json &params, iora::rpc::RpcContext &) { return params; });
    s.registerMethod("boom", [](const Json &, iora::rpc::RpcContext &) -> Json
                     { throw std::runtime_error("boom"); });
  };
  return o;
}

// ── /capture counterparty: a raw HttpServer recording the request Accept-Encoding
//    and replying per an installable policy (default: 200 + kOkResult, verbatim —
//    id=1 correlates with a fresh client's first call). Replaces the plugin
//    webhookServer.
class CaptureServer
{
public:
  struct State
  {
    std::mutex m;
    int count = 0;
    std::vector<std::string> reqAcceptEncoding; // request Accept-Encoding per call ("" if absent)
    // policy(idx, res): craft the response verbatim. Default: 200 + kOkResult identity.
    std::function<void(int, iora::network::HttpServer::Response &)> policy;
  };

  CaptureServer() : _port(testnet::getFreePortTCP()), _http("127.0.0.1", static_cast<int>(_port))
  {
    _http.onPost("/capture",
                 [this](const iora::network::HttpServer::Request &req,
                        iora::network::HttpServer::Response &res)
                 {
                   std::function<void(int, iora::network::HttpServer::Response &)> policy;
                   int idx;
                   {
                     std::lock_guard<std::mutex> lk(_state.m);
                     idx = _state.count++;
                     _state.reqAcceptEncoding.push_back(
                       req.has_header("Accept-Encoding") ? req.get_header_value("Accept-Encoding")
                                                         : "");
                     policy = _state.policy; // copy-then-invoke
                   }
                   if (policy)
                   {
                     policy(idx, res);
                   }
                   else
                   {
                     res.status = 200;
                     res.set_content(kOkResult, "application/json");
                   }
                 });
    _http.start();
    std::this_thread::sleep_for(200ms);
  }
  ~CaptureServer() { _http.stop(); }

  CaptureServer(const CaptureServer &) = delete;
  CaptureServer &operator=(const CaptureServer &) = delete;

  std::string url() const { return "http://127.0.0.1:" + std::to_string(_port) + "/capture"; }
  State &state() { return _state; }

private:
  std::uint16_t _port;
  iora::network::HttpServer _http;
  State _state;
};

// Craft a /capture response with a literal Content-Encoding header and a body.
void setCe(iora::network::HttpServer::Response &res, const std::string &contentEncoding,
           const std::string &body)
{
  res.status = 200;
  res.set_header("Content-Encoding", contentEncoding);
  res.set_content(body, "application/json");
}

Config clientConfig(bool advertise = true, std::size_t maxDecoded = 16 * 1024 * 1024)
{
  Config cfg;
  cfg.maxRetries = 0;
  cfg.advertiseAcceptEncoding = advertise;
  cfg.maxDecodedResponseBytes = maxDecoded;
  // enableRequestCompression stays false (default): this suite is response-direction.
  return cfg;
}

// ── minimal raw responder (two physical Content-Encoding lines, defect_8) ─────
struct RawResponder
{
  int listenFd = -1;
  std::uint16_t port;
  std::thread th;
  std::atomic<bool> stop{false};
  std::string rawResponse;

  explicit RawResponder(std::string response)
      : port(testnet::getFreePortTCP()), rawResponse(std::move(response))
  {
    listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(listenFd >= 0);
    int one = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");
    REQUIRE(::bind(listenFd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    REQUIRE(::listen(listenFd, 4) == 0);
    th = std::thread([this] { loop(); });
    std::this_thread::sleep_for(100ms);
  }

  void loop()
  {
    while (!stop.load())
    {
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(listenFd, &rfds);
      timeval tv{0, 100000}; // 100ms
      if (::select(listenFd + 1, &rfds, nullptr, nullptr, &tv) <= 0)
      {
        continue;
      }
      int conn = ::accept(listenFd, nullptr, nullptr);
      if (conn < 0)
      {
        continue;
      }
      char buf[8192];
      ::recv(conn, buf, sizeof(buf), 0); // drain the request head (small body)
      ::send(conn, rawResponse.data(), rawResponse.size(), 0);
      ::close(conn);
    }
  }

  ~RawResponder()
  {
    stop.store(true);
    if (th.joinable())
    {
      th.join();
    }
    if (listenFd >= 0)
    {
      ::close(listenFd);
    }
  }
};

std::string rawHttpResponse(const std::string &headers, const std::string &body)
{
  return "HTTP/1.1 200 OK\r\n" + headers + "Content-Length: " + std::to_string(body.size()) +
         "\r\nConnection: close\r\n\r\n" + body;
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
// SERVER compress — enableResponseCompression=true, low threshold. Driven with a
// raw HttpClient against the composed /rpc endpoint.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip response server: negotiation matrix (enabled, low threshold)",
          "[gzip-response][server]")
{
  testrpc::ComposedRpcServer server(serverOpts(/*responseCompression=*/true, /*threshold=*/32));
  iora::network::HttpClient http;
  const std::string url = server.url();
  const std::string payload(200, 'a'); // result envelope comfortably over threshold 32
  const std::string req = echoReq(payload);

  SECTION("Accept-Encoding: gzip -> compressed, Content-Encoding+Vary, CL over compressed")
  {
    auto r = http.post(url, req,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    auto ce = r.headers.find("Content-Encoding");
    REQUIRE(ce != r.headers.end());
    REQUIRE(ce->second == "gzip");
    REQUIRE(r.headers.find("Vary") != r.headers.end());
    REQUIRE(r.headers.find("Vary")->second == "Accept-Encoding");
    REQUIRE(r.headers.find("Content-Type")->second.find("application/json") != std::string::npos);
    // Compress-before-Content-Length: the body IS gzip (inflates to the envelope) and
    // Content-Length is over the COMPRESSED bytes (smaller than the plaintext).
    const std::string inflated = gunzip(r.body);
    REQUIRE(inflated.find(payload) != std::string::npos);
    REQUIRE(r.body.size() < inflated.size());
    REQUIRE(std::stoul(r.headers.find("Content-Length")->second) == r.body.size());
  }

  SECTION("Accept-Encoding: gzip;q=0 -> identity + Vary (not acceptable)")
  {
    auto r = http.post(url, req,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip;q=0"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
    REQUIRE(r.headers.find("Vary") != r.headers.end());
    REQUIRE(r.body.find(payload) != std::string::npos); // identity plaintext
  }

  SECTION("no Accept-Encoding -> identity + Vary")
  {
    auto r = http.post(url, req, {{"Content-Type", "application/json"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
    REQUIRE(r.headers.find("Vary") != r.headers.end());
    REQUIRE(r.body.find(payload) != std::string::npos);
  }

  SECTION("Accept-Encoding: identity;q=0 -> identity, NOT 406 (RFC 9110 §12.5.3)")
  {
    auto r = http.post(
      url, req, {{"Content-Type", "application/json"}, {"Accept-Encoding", "identity;q=0"}}, 0);
    REQUIRE(r.statusCode == 200); // never 406
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
    REQUIRE(r.headers.find("Vary") != r.headers.end());
  }

  SECTION("case-insensitive coding token: 'GZIP' -> compressed (RFC 9110 §8.4.1)")
  {
    auto r = http.post(url, req,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "GZIP"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") != r.headers.end());
    REQUIRE(gunzip(r.body).find(payload) != std::string::npos);
  }

  SECTION("'*' fallback with non-zero q -> compressed")
  {
    auto r = http.post(url, req,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "*"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") != r.headers.end());
  }

  SECTION("Accept-Encoding: x-gzip -> compressed (legacy alias, RFC 9110 §8.4.1)")
  {
    auto r = http.post(url, req,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "x-gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") != r.headers.end());
    REQUIRE(r.headers.find("Content-Encoding")->second == "gzip"); // emit gzip, never x-gzip
    REQUIRE(gunzip(r.body).find(payload) != std::string::npos);
  }

  SECTION("204 notification never carries Content-Encoding")
  {
    auto r = http.post(url, echoNotify(payload),
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 204);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
  }

  SECTION("204 successful notification has an empty body and no Content-Length/Content-Type (CR-6)")
  {
    auto r = http.post(url, echoNotify(payload),
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 204);
    REQUIRE(r.body.empty());
    REQUIRE(r.headers.find("Content-Length") == r.headers.end());
    REQUIRE(r.headers.find("Content-Type") == r.headers.end());
  }

  SECTION("204 failed notification (unknown method) is body-less with no framing headers (CR-6 + W-H1)")
  {
    const std::string notifyUnknown = R"({"jsonrpc":"2.0","method":"nope","params":{}})";
    auto r = http.post(url, notifyUnknown,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 204);
    REQUIRE(r.body.empty());
    REQUIRE(r.headers.find("Content-Length") == r.headers.end());
    REQUIRE(r.headers.find("Content-Type") == r.headers.end());
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
  }

  SECTION("media-type 415 error body stays identity, no Vary")
  {
    auto r = http.post(url, req,
                       {{"Content-Type", "text/plain"}, {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 415);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
    REQUIRE(r.headers.find("Vary") == r.headers.end());
    REQUIRE(r.body.find("Unsupported Media Type") != std::string::npos); // envelope message
  }
}

TEST_CASE("gzip response server: sub-threshold body stays identity but still Varies",
          "[gzip-response][server]")
{
  // High threshold: any normal echo result is sub-threshold -> identity. Vary is
  // still emitted (uniform Vary set across all representations when compression is ON).
  testrpc::ComposedRpcServer server(serverOpts(/*responseCompression=*/true, /*threshold=*/1000000));
  iora::network::HttpClient http;
  const std::string req = echoReq("small");

  auto r = http.post(server.url(), req,
                     {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
  REQUIRE(r.statusCode == 200);
  REQUIRE(r.headers.find("Content-Encoding") == r.headers.end()); // sub-threshold -> identity
  REQUIRE(r.headers.find("Vary") != r.headers.end());
  REQUIRE(r.body.find("small") != std::string::npos);
}

TEST_CASE("gzip response server: compression DISABLED emits no Vary and no Content-Encoding",
          "[gzip-response][server]")
{
  testrpc::ComposedRpcServer server(serverOpts(/*responseCompression=*/false, /*threshold=*/32));
  iora::network::HttpClient http;
  const std::string req = echoReq(std::string(200, 'a'));

  auto r = http.post(server.url(), req,
                     {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
  REQUIRE(r.statusCode == 200);
  REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
  REQUIRE(r.headers.find("Vary") == r.headers.end()); // no negotiation -> no Vary
}

TEST_CASE("gzip response server: 401 error body stays identity", "[gzip-response][server]")
{
  testrpc::ComposedRpcServer server(serverOpts(/*responseCompression=*/true, /*threshold=*/32, /*auth=*/true));
  iora::network::HttpClient http;
  const std::string req = echoReq(std::string(200, 'a'));

  // No Authorization header -> 401. Even with Accept-Encoding: gzip, the error body
  // is never compressed and carries no Vary.
  auto r = http.post(server.url(), req,
                     {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
  REQUIRE(r.statusCode == 401);
  REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
  REQUIRE(r.headers.find("Vary") == r.headers.end());
}

TEST_CASE("gzip response server: 400/413/500 error bodies stay identity under compression",
          "[gzip-response][server]")
{
  // enableResponseCompression=true AND enableRequestDecompression=true, so a request
  // carrying Accept-Encoding: gzip can still reach a 400 (malformed request coding),
  // 413 (decoded overflow), or a method-throw (JSON-RPC error at 200).
  testrpc::ComposedRpcServer server(serverOpts(/*responseCompression=*/true, /*threshold=*/32,
                                               /*auth=*/false, /*requestDecompression=*/true));
  iora::network::HttpClient http;
  const std::string url = server.url();

  SECTION("a method-throw is a JSON-RPC error at HTTP 200 and IS compressed (2xx negotiated)")
  {
    const std::string boom = R"({"jsonrpc":"2.0","method":"boom","params":{},"id":1})";
    auto r = http.post(url, boom,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") != r.headers.end());
    REQUIRE(r.headers.find("Content-Encoding")->second == "gzip");
    REQUIRE(gunzip(r.body).find("\"error\"") != std::string::npos); // JSON-RPC error envelope
  }

  SECTION("400 (malformed request coding): identity, no Content-Encoding, no Vary")
  {
    auto r = http.post(url, "this-is-not-gzip",
                       {{"Content-Type", "application/json"},
                        {"Content-Encoding", "gzip"},
                        {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 400);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
    REQUIRE(r.headers.find("Vary") == r.headers.end());
  }

  SECTION("413 (decoded request overflow): identity, no Content-Encoding, no Vary")
  {
    const std::string bomb = gz(std::string(2 * 1024 * 1024, 'a'));
    REQUIRE(bomb.size() < 1024u * 1024);
    auto r = http.post(url, bomb,
                       {{"Content-Type", "application/json"},
                        {"Content-Encoding", "gzip"},
                        {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 413);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
    REQUIRE(r.headers.find("Vary") == r.headers.end());
  }
}

TEST_CASE("gzip response server: two physical Accept-Encoding lines still negotiate gzip (W-M1)",
          "[gzip-response][server]")
{
  // HttpClient's map API cannot emit duplicate field lines, so drive it raw. The
  // server combines the two Accept-Encoding lines into "gzip, identity;q=0" on
  // ingress (RFC 9110 §5.3), then gzipAcceptable sees gzip q=1.
  testrpc::ComposedRpcServer server(serverOpts(/*responseCompression=*/true, /*threshold=*/32));
  const std::string req = echoReq(std::string(200, 'a'));
  const std::string reqBytes = "POST /rpc HTTP/1.1\r\n"
                               "Host: localhost:" +
                               std::to_string(server.port()) +
                               "\r\n"
                               "Content-Type: application/json\r\n"
                               "Accept-Encoding: gzip\r\n"
                               "Accept-Encoding: identity;q=0\r\n"
                               "Content-Length: " +
                               std::to_string(req.size()) +
                               "\r\n"
                               "Connection: close\r\n\r\n" +
                               req;
  const std::string resp = testnet::rawHttpRequest(server.port(), reqBytes);
  REQUIRE(resp.find("HTTP/1.1 200") != std::string::npos);
  REQUIRE(iora::core::StringUtils::iequals(rawHeader(resp, "Content-Encoding"), "gzip"));
  REQUIRE(rawHeader(resp, "Vary") == "Accept-Encoding");
}

// ═════════════════════════════════════════════════════════════════════════════
// CLIENT decode — JsonRpcClient (advertises gzip) against a /capture handler that
// crafts Content-Encoding responses. The crafted bodies use id=1, matching a fresh
// client's first call (task-5b.3 id-correlation).
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip response client: DP-6 decode matrix over crafted Content-Encoding",
          "[gzip-response][client]")
{
  CaptureServer server;
  auto &rcap = server.state();
  iora::core::ThreadPool pool(2, 2, 1s);
  const std::string ep = server.url();
  const Json params = Json::object();
  JsonRpcClient client(pool, clientConfig());

  SECTION("single 'gzip' body decodes")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "gzip", gz(kOkResult)); };
    auto r = client.call(ep, "echo", params);
    REQUIRE(r.is_object());
    REQUIRE(r["ok"].get<bool>() == true);
  }

  SECTION("ordered 'identity, gzip' decodes outermost-first (DP-6)")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "identity, gzip", gz(kOkResult)); };
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("stacked 'gzip, gzip' double-decodes (DP-6)")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "gzip, gzip", gz(gz(kOkResult))); };
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("empty elements 'gzip,,' skipped (§5.6.1)")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "gzip,,", gz(kOkResult)); };
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("leading empty ' , gzip' skipped (§5.6.1)")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, " , gzip", gz(kOkResult)); };
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("'x-gzip' decodes as gzip (§8.4.1 legacy alias)")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "x-gzip", gz(kOkResult)); };
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("mixed-case 'GZIP' decodes (§8.4.1 case-insensitive)")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "GZIP", gz(kOkResult)); };
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION(">2 stacked codings rejected before decode (DP-6 hard cap)")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "gzip, gzip, gzip", gz(gz(gz(kOkResult)))); };
    REQUIRE_THROWS_AS(client.call(ep, "echo", params), JsonRpcError);
  }

  SECTION("unknown coding 'br' throws (fail loudly, DP-6)")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "br", kOkResult); };
    REQUIRE_THROWS_AS(client.call(ep, "echo", params), JsonRpcError);
  }

  SECTION("malformed gzip body throws")
  {
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "gzip", "not-actually-gzip-bytes"); };
    REQUIRE_THROWS_AS(client.call(ep, "echo", params), JsonRpcError);
  }
}

TEST_CASE("gzip response client: caps + advertise (DP-5/caps.client)", "[gzip-response][client]")
{
  CaptureServer server;
  auto &rcap = server.state();
  iora::core::ThreadPool pool(2, 2, 1s);
  const std::string ep = server.url();
  const Json params = Json::object();

  SECTION("advertise=true emits Accept-Encoding: gzip")
  {
    JsonRpcClient client(pool, clientConfig(/*advertise=*/true));
    REQUIRE(client.call(ep, "echo", params).is_object());
    std::lock_guard<std::mutex> lk(rcap.m);
    REQUIRE(rcap.reqAcceptEncoding.size() == 1);
    REQUIRE(rcap.reqAcceptEncoding[0] == "gzip");
  }

  SECTION("advertise=false emits Accept-Encoding: identity and still decodes gzip")
  {
    // A false advertiser positively suppresses server compression, but if a server
    // gzips anyway the decoder still inflates it (advertise gates only the header).
    rcap.policy = [](int, iora::network::HttpServer::Response &res)
    { setCe(res, "gzip", gz(kOkResult)); };
    JsonRpcClient client(pool, clientConfig(/*advertise=*/false));
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
    std::lock_guard<std::mutex> lk(rcap.m);
    REQUIRE(rcap.reqAcceptEncoding[0] == "identity");
  }

  SECTION("decoded body in (10 MiB, maxDecodedResponseBytes] passes (cap alignment)")
  {
    // ~11.4 MiB inflated JSON, over the 10 MiB single-arg parse default and under the
    // 16 MiB maxDecodedResponseBytes: passes ONLY because sendJson_ aligns the parse
    // cap to maxDecodedResponseBytes for the decoded path.
    std::string arr = "[";
    for (int i = 0; i < 15; ++i)
    {
      arr += (i == 0 ? "\"" : ",\"") + std::string(800 * 1000, 'a') + "\"";
    }
    arr += "]";
    const std::string big = R"({"jsonrpc":"2.0","result":{"blob":)" + arr + R"(},"id":1})";
    REQUIRE(big.size() > 10u * 1024 * 1024);
    REQUIRE(big.size() < 16u * 1024 * 1024);
    const std::string gzBig = gz(big);
    REQUIRE(gzBig.size() < 1024u * 1024); // fits the 1 MiB sync-receive buffer
    rcap.policy = [gzBig](int, iora::network::HttpServer::Response &res)
    { setCe(res, "gzip", gzBig); };
    JsonRpcClient client(pool, clientConfig(true, 16 * 1024 * 1024));
    auto r = client.call(ep, "echo", params);
    REQUIRE(r.is_object());
    REQUIRE(r["blob"].is_array());
    REQUIRE(r["blob"].size() == 15u);
  }

  SECTION("identity-path parse cap tracks maxDecodedResponseBytes, not the 10 MiB default")
  {
    const std::string body =
      R"({"jsonrpc":"2.0","result":{"pad":")" + std::string(600, 'x') + R"("},"id":1})";
    rcap.policy = [body](int, iora::network::HttpServer::Response &res)
    {
      res.status = 200;
      res.set_content(body, "application/json"); // identity, no Content-Encoding
    };

    // maxDecoded = 400 < body (~640): identity path enforces the aligned cap and
    // parseJsonOrThrow throws ("exceeds maximum size limit of 400 bytes").
    {
      JsonRpcClient tight(pool, clientConfig(true, /*maxDecoded=*/400));
      REQUIRE_THROWS_WITH(tight.call(ep, "echo", params),
                          Catch::Contains("maximum size limit of 400"));
    }
    // maxDecoded large: the SAME identity body passes.
    {
      JsonRpcClient loose(pool, clientConfig(true, /*maxDecoded=*/16 * 1024 * 1024));
      REQUIRE(loose.call(ep, "echo", params).is_object());
    }
  }

  SECTION("response zip-bomb rejected within maxDecodedResponseBytes (DP-5)")
  {
    // 4 MiB of 'a' compresses tiny (passes the compressed wire guard) but inflates
    // past a 64 KiB decoded cap -> OUTPUT_TOO_LARGE -> JsonRpcError.
    const std::string bomb = gz(std::string(4 * 1024 * 1024, 'a'));
    rcap.policy = [bomb](int, iora::network::HttpServer::Response &res)
    { setCe(res, "gzip", bomb); };
    JsonRpcClient client(pool, clientConfig(true, /*maxDecoded=*/64 * 1024));
    REQUIRE_THROWS_AS(client.call(ep, "echo", params), JsonRpcError);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// CLIENT decode — defect_8 regression: two PHYSICAL Content-Encoding response lines
// combine (RFC 9110 §5.3) and double-decode. Driven with a raw responder because a
// map-based server cannot emit duplicate field lines.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip response client: two physical Content-Encoding lines combine + decode (defect_8)",
          "[gzip-response][client]")
{
  iora::core::ThreadPool pool(2, 2, 1s);
  const std::string body = gz(gz(kOkResult)); // double-gzipped -> "gzip, gzip" decodes it
  RawResponder responder(rawHttpResponse("Content-Type: application/json\r\n"
                                         "Content-Encoding: gzip\r\n"
                                         "Content-Encoding: gzip\r\n",
                                         body));

  JsonRpcClient client(pool, clientConfig());
  const std::string url = "http://127.0.0.1:" + std::to_string(responder.port) + "/rpc";
  auto r = client.call(url, "echo", Json::object());
  REQUIRE(r.is_object());
  REQUIRE(r["ok"].get<bool>() == true);
}

// ═════════════════════════════════════════════════════════════════════════════
// FULL ROUND-TRIP — real JsonRpcClient (advertises gzip) <-> composed server
// (compresses): the client decodes what the server compressed.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip response round-trip: real client decodes a real server-compressed response",
          "[gzip-response][roundtrip]")
{
  testrpc::ComposedRpcServer server(serverOpts(/*responseCompression=*/true, /*threshold=*/32));
  iora::core::ThreadPool pool(2, 2, 1s);

  JsonRpcClient client(pool, clientConfig(/*advertise=*/true));
  Json params = Json::object();
  params["x"] = std::string(500, 'z'); // result over the server threshold -> compressed

  auto r = client.call(server.url(), "echo", params);
  REQUIRE(r.is_object());
  REQUIRE(r["x"].get<std::string>() == std::string(500, 'z'));
}
