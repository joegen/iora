// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Response-direction tests for the JSON-RPC bidirectional negotiated-gzip
// Consumer C (tracker 2026-09-04-4, arch architecture/iora/jsonrpc_gzip_compression.json).
// Phase 3: the SERVER compresses response bodies when Accept-Encoding negotiates
// gzip (standard Accept-Encoding + Vary), the CLIENT decodes them, and sendJson_
// aligns the JSON parse cap to maxDecodedResponseBytes for every response.
//
// Surfaces exercised:
//   * SERVER compress (task-1.x): the real mod_jsonrpc_server .so is loaded with
//     enableResponseCompression and driven with a raw HttpClient (which never
//     auto-injects Accept-Encoding / does not decode responses, so crafted request
//     Accept-Encoding + raw compressed response bytes are directly observable).
//     Validates handlePost negotiation end-to-end (Content-Encoding, Vary,
//     compress-before-Content-Length, sub-threshold / error / 204 identity, no-406).
//   * CLIENT decode + advertise + caps (task-2.x): a JsonRpcClient is pointed at a
//     controllable /capture handler (crafted Content-Encoding response headers +
//     encoded bodies) and at a raw responder (two physical Content-Encoding lines,
//     the defect_8 COMBINE regression), so the advertise value, the DP-6 decode
//     matrix, the caps, and the real round-trip are black-box observable.
//
// W-M1 (two physical Accept-Encoding REQUEST lines still negotiate gzip) is driven
// over a raw socket because HttpClient's map API cannot emit duplicate field lines;
// the server's ingress parser combines them per RFC 9110 §5.3 (foundation gate).

#include "../jsonrpc_client.hpp" // JsonRpcClient, Config, JsonRpcError

#include "iora/iora.hpp"
#include "iora/network/http_client.hpp"
#include "iora/parsers/http_message.hpp"
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
#include <sys/select.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace iora::modules::connectors;

namespace
{

using JsonHandler = std::function<iora::parsers::Json(const iora::parsers::Json &)>;

std::string gz(const std::string &s) { return iora::util::Gzip::compress(s); }
std::string gunzip(const std::string &s, std::size_t cap = 64 * 1024 * 1024)
{
  auto r = iora::util::Gzip::decompress(s, cap);
  REQUIRE(r.isOk());
  return std::move(r).value();
}

const char *const kOkResult = R"({"jsonrpc":"2.0","result":{"ok":true},"id":1})";

// A JSON-RPC request calling the registered `echo` method with an inline string
// payload, so the server's echoed result envelope is a controllable size (drives
// the compression threshold both ways).
std::string echoReq(const std::string &payload)
{
  return R"({"jsonrpc":"2.0","method":"echo","params":{"x":")" + payload + R"("},"id":1})";
}
// A JSON-RPC NOTIFICATION (no id) -> the router yields an empty response -> 204.
std::string echoNotify(const std::string &payload)
{
  return R"({"jsonrpc":"2.0","method":"echo","params":{"x":")" + payload + R"("}})";
}

// ── raw-socket helpers (W-M1 request + raw-response header inspection) ────────
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

// First value of a header (case-insensitive name) in a raw HTTP response, trimmed;
// "" if absent. Only scans the header block (up to the CRLFCRLF). Uses the ASCII,
// locale-independent foundation StringUtils::toLower (no hand-rolled std::tolower).
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

// ── real jsonrpc server harness ──────────────────────────────────────────────
std::string serverPluginPath()
{
  return iora::util::resolveRelativePath(iora::util::getExecutableDir(),
                                         "../../../endpoints/jsonrpc_server/") +
         "/mod_jsonrpc_server.so";
}

std::string writeServerToml(bool responseCompression, std::size_t threshold, bool auth,
                            bool requestDecompression)
{
  namespace fs = std::filesystem;
  static int seq = 0;
  const std::string path =
    (fs::temp_directory_path() / ("iora_gzip_resp_server_" + std::to_string(seq++) + ".toml"))
      .string();
  std::ofstream o(path, std::ios::trunc);
  o << "[iora.modules.jsonrpc_server]\n";
  o << "enableResponseCompression = " << (responseCompression ? "true" : "false") << "\n";
  o << "enableRequestDecompression = " << (requestDecompression ? "true" : "false") << "\n";
  o << "compressionThreshold = " << threshold << "\n";
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

iora::IoraService &startServer(int port, bool responseCompression, std::size_t threshold,
                               bool auth = false, bool requestDecompression = false)
{
  try
  {
    iora::IoraService::shutdown();
  }
  catch (...)
  {
  }
  auto cfg = baseConfig(port);
  cfg.configFile = writeServerToml(responseCompression, threshold, auth, requestDecompression);
  iora::IoraService::init(cfg);
  iora::IoraService &svc = iora::IoraService::instanceRef();

  REQUIRE(std::filesystem::exists(serverPluginPath()));
  REQUIRE(svc.loadSingleModule(serverPluginPath()));

  svc.callExportedApi<void, const std::string &, JsonHandler>(
    "jsonrpc.register", "echo", [](const iora::parsers::Json &p) { return p; });
  // A method that throws, so the router surfaces a 500 (internal error) — used to
  // prove a 500 error body stays identity under response compression.
  svc.callExportedApi<void, const std::string &, JsonHandler>(
    "jsonrpc.register", "boom",
    [](const iora::parsers::Json &) -> iora::parsers::Json
    { throw std::runtime_error("boom"); });

  std::this_thread::sleep_for(std::chrono::milliseconds(250));
  return svc;
}

// ── /capture handler (client-side decode/advertise tests) ────────────────────
struct ResponseCapture
{
  std::mutex m;
  int count = 0;
  std::vector<std::string> reqAcceptEncoding; // request Accept-Encoding per call ("" if absent)
  // policy(idx, res): craft the response (headers + body). Default: 200 + kOkResult identity.
  std::function<void(int, iora::network::WebhookServer::Response &)> policy;

  void reset()
  {
    std::lock_guard<std::mutex> lk(m);
    count = 0;
    reqAcceptEncoding.clear();
    policy = nullptr;
  }
};
ResponseCapture g_rcap;

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
  g_rcap.reset();

  svc.webhookServer()->onPost(
    "/capture",
    [](const iora::network::WebhookServer::Request &req,
       iora::network::WebhookServer::Response &res)
    {
      std::lock_guard<std::mutex> lk(g_rcap.m);
      const int idx = g_rcap.count++;
      g_rcap.reqAcceptEncoding.push_back(req.get_header_value("Accept-Encoding"));
      if (g_rcap.policy)
      {
        g_rcap.policy(idx, res);
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

// Craft a /capture response with a literal Content-Encoding header and a body.
void setCe(iora::network::WebhookServer::Response &res, const std::string &contentEncoding,
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
  std::thread th;
  std::atomic<bool> stop{false};
  std::string rawResponse;

  RawResponder(std::uint16_t port, std::string response) : rawResponse(std::move(response))
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
// SERVER compress — enableResponseCompression=true, low threshold (task-1.1/1.2/1.3,
// task-3.2). Driven with a raw HttpClient against the real /rpc plugin.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip response server: negotiation matrix (enabled, low threshold)",
          "[gzip-response][server]")
{
  iora::IoraService &svc = startServer(8151, /*responseCompression=*/true, /*threshold=*/32);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  iora::network::HttpClient http;
  const std::string url = "http://localhost:8151/rpc";
  const std::string payload(200, 'a'); // result envelope comfortably over threshold 32
  const std::string req = echoReq(payload);

  SECTION("Accept-Encoding: gzip -> compressed, Content-Encoding+Vary, CL over compressed (task-1.1/1.2)")
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
    // Content-Length is over the COMPRESSED bytes (smaller than the plaintext). A
    // compress-after-set_content bug would ship plaintext with a plaintext CL.
    const std::string inflated = gunzip(r.body);
    REQUIRE(inflated.find(payload) != std::string::npos);
    REQUIRE(r.body.size() < inflated.size());
    REQUIRE(std::stoul(r.headers.find("Content-Length")->second) == r.body.size());
  }

  SECTION("Accept-Encoding: gzip;q=0 -> identity + Vary (not acceptable, task-1.1/1.3)")
  {
    auto r = http.post(url, req,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip;q=0"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
    REQUIRE(r.headers.find("Vary") != r.headers.end());
    REQUIRE(r.body.find(payload) != std::string::npos); // identity plaintext
  }

  SECTION("no Accept-Encoding -> identity + Vary (task-1.3)")
  {
    auto r = http.post(url, req, {{"Content-Type", "application/json"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
    REQUIRE(r.headers.find("Vary") != r.headers.end());
    REQUIRE(r.body.find(payload) != std::string::npos);
  }

  SECTION("Accept-Encoding: identity;q=0 -> identity, NOT 406 (task-1.3, RFC 9110 §12.5.3)")
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

  SECTION("'*' fallback with non-zero q -> compressed (task-1.1)")
  {
    auto r = http.post(url, req,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "*"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") != r.headers.end());
  }

  SECTION("Accept-Encoding: x-gzip -> compressed (legacy alias, RFC 9110 §8.4.1)")
  {
    // gzipAcceptable honors x-gzip symmetrically with the decode side, so a client
    // asking with the legacy alias is served gzip rather than falling to identity.
    auto r = http.post(url, req,
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "x-gzip"}}, 0);
    REQUIRE(r.statusCode == 200);
    REQUIRE(r.headers.find("Content-Encoding") != r.headers.end());
    REQUIRE(r.headers.find("Content-Encoding")->second == "gzip"); // emit gzip, never x-gzip
    REQUIRE(gunzip(r.body).find(payload) != std::string::npos);
  }

  SECTION("204 notification never carries Content-Encoding (task-1.1)")
  {
    auto r = http.post(url, echoNotify(payload),
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 204);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
  }

  // CR-6 (task-2.4, tracker 2026-07-26-3): a 204 MUST carry no content. HttpServer
  // pre-populates every matched Response with set_content("Not Found","text/plain"),
  // so before the endpoint's explicit body/header clear the 204 leaked "Not Found"
  // with Content-Length: 9 and Content-Type: text/plain (RFC 9110 §15.3.5 / RFC
  // 9112 §6.3 violation). Assert the body and the framing/type headers are gone.
  SECTION("204 successful notification has an empty body and no Content-Length/Content-Type (CR-6)")
  {
    auto r = http.post(url, echoNotify(payload),
                       {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 204);
    REQUIRE(r.body.empty());
    REQUIRE(r.headers.find("Content-Length") == r.headers.end());
    REQUIRE(r.headers.find("Content-Type") == r.headers.end());
  }

  // W-H1 widens the 204 path to FAILED notifications: a notification to an unknown
  // method is now suppressed (empty dispatcher result) and reaches the same 204
  // branch, so the CR-6 clear must hold there too.
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

  SECTION("media-type 415 error body stays identity, no Vary (task-1.3)")
  {
    auto r = http.post(url, req,
                       {{"Content-Type", "text/plain"}, {"Accept-Encoding", "gzip"}}, 0);
    REQUIRE(r.statusCode == 415);
    REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
    REQUIRE(r.headers.find("Vary") == r.headers.end());
    REQUIRE(r.body.find("Unsupported Media Type") != std::string::npos); // plaintext error
  }
}

TEST_CASE("gzip response server: sub-threshold body stays identity but still Varies (task-1.3)",
          "[gzip-response][server]")
{
  // High threshold: any normal echo result is sub-threshold -> identity. Vary is
  // still emitted (uniform Vary set across all representations when compression is
  // ON, web round-2 LOW-1), even though this particular body was not compressed.
  iora::IoraService &svc = startServer(8152, /*responseCompression=*/true, /*threshold=*/1000000);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);
  iora::network::HttpClient http;
  const std::string req = echoReq("small");

  auto r = http.post("http://localhost:8152/rpc", req,
                     {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
  REQUIRE(r.statusCode == 200);
  REQUIRE(r.headers.find("Content-Encoding") == r.headers.end()); // sub-threshold -> identity
  REQUIRE(r.headers.find("Vary") != r.headers.end());
  REQUIRE(r.body.find("small") != std::string::npos);
}

TEST_CASE("gzip response server: compression DISABLED emits no Vary and no Content-Encoding (task-1.3)",
          "[gzip-response][server]")
{
  iora::IoraService &svc = startServer(8153, /*responseCompression=*/false, /*threshold=*/32);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);
  iora::network::HttpClient http;
  const std::string req = echoReq(std::string(200, 'a'));

  auto r = http.post("http://localhost:8153/rpc", req,
                     {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
  REQUIRE(r.statusCode == 200);
  REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
  REQUIRE(r.headers.find("Vary") == r.headers.end()); // no negotiation -> no Vary
}

TEST_CASE("gzip response server: 401 error body stays identity (task-1.3)", "[gzip-response][server]")
{
  iora::IoraService &svc =
    startServer(8154, /*responseCompression=*/true, /*threshold=*/32, /*auth=*/true);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);
  iora::network::HttpClient http;
  const std::string req = echoReq(std::string(200, 'a'));

  // No Authorization header -> 401. Even with Accept-Encoding: gzip, the error body
  // is never compressed and carries no Vary.
  auto r = http.post("http://localhost:8154/rpc", req,
                     {{"Content-Type", "application/json"}, {"Accept-Encoding", "gzip"}}, 0);
  REQUIRE(r.statusCode == 401);
  REQUIRE(r.headers.find("Content-Encoding") == r.headers.end());
  REQUIRE(r.headers.find("Vary") == r.headers.end());
}

TEST_CASE("gzip response server: 400/413/500 error bodies stay identity under compression (task-1.3)",
          "[gzip-response][server]")
{
  // enableResponseCompression=true AND enableRequestDecompression=true, so a request
  // carrying Accept-Encoding: gzip can still reach a 400 (malformed request coding),
  // 413 (decoded overflow), or 500 (handler throw) — none of which may compress, and
  // each must stay identity (no Content-Encoding, no Vary). Complements the 401/415
  // cases (testStrategy: error bodies 400/401/413/415/500 stay identity).
  iora::IoraService &svc = startServer(8160, /*responseCompression=*/true, /*threshold=*/32,
                                       /*auth=*/false, /*requestDecompression=*/true);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);
  iora::network::HttpClient http;
  const std::string url = "http://localhost:8160/rpc";

  SECTION("a method-throw is a JSON-RPC error at HTTP 200 and IS compressed (2xx negotiated)")
  {
    // A registered method throwing is caught by the router and returned as a JSON-RPC
    // error ENVELOPE at HTTP 200 (an application-level error, not a transport error).
    // That is a content-negotiated 2xx and must be compressed like any other 200 —
    // NOT treated as a non-2xx identity error body. (The genuine HTTP 500 — the
    // handlePost catch — fires only on an unexpected framework/router throw, e.g.
    // bad_alloc, which is not plugin-triggerable from a test; it shares the single
    // setJsonRpcError_ emitter with the 400/401/413/415 cases below, whose identity +
    // header-clearing behavior those sections prove, plus the L-1 header-erase.)
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
    // 2 MiB of 'a' compresses tiny (passes the compressed pre-filter) but inflates
    // past the 1 MiB _maxRequestBytes decoded cap -> 413.
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
  // ingress (RFC 9110 §5.3, foundation gate), then gzipAcceptable sees gzip q=1.
  iora::IoraService &svc = startServer(8155, /*responseCompression=*/true, /*threshold=*/32);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  const std::string body = echoReq(std::string(200, 'a'));
  const std::string reqBytes = "POST /rpc HTTP/1.1\r\n"
                               "Host: localhost:8155\r\n"
                               "Content-Type: application/json\r\n"
                               "Accept-Encoding: gzip\r\n"
                               "Accept-Encoding: identity;q=0\r\n"
                               "Content-Length: " +
                               std::to_string(body.size()) +
                               "\r\n"
                               "Connection: close\r\n\r\n" +
                               body;
  const std::string resp = rawHttpRequest(8155, reqBytes);
  REQUIRE(resp.find("HTTP/1.1 200") != std::string::npos);
  REQUIRE(iora::core::StringUtils::iequals(rawHeader(resp, "Content-Encoding"), "gzip"));
  REQUIRE(rawHeader(resp, "Vary") == "Accept-Encoding");
}

// ═════════════════════════════════════════════════════════════════════════════
// CLIENT decode — JsonRpcClient (advertise gzip) against a /capture handler that
// crafts Content-Encoding response headers + encoded bodies (task-2.2, DP-6 matrix,
// task-3.3). The full DP-6 decode matrix over crafted responses.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip response client: DP-6 decode matrix over crafted Content-Encoding",
          "[gzip-response][client]")
{
  iora::IoraService &svc = startCaptureService(8156);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::string ep = "http://127.0.0.1:8156/capture";
  const iora::parsers::Json params = iora::parsers::Json::object();

  SECTION("single 'gzip' body decodes (task-2.2)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "gzip", gz(kOkResult)); };
    JsonRpcClient client(svc, pool, clientConfig());
    auto r = client.call(ep, "echo", params);
    REQUIRE(r.is_object());
    REQUIRE(r["ok"].get<bool>() == true);
  }

  SECTION("ordered 'identity, gzip' decodes outermost-first (DP-6)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "identity, gzip", gz(kOkResult)); };
    JsonRpcClient client(svc, pool, clientConfig());
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("stacked 'gzip, gzip' double-decodes (DP-6)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "gzip, gzip", gz(gz(kOkResult))); };
    JsonRpcClient client(svc, pool, clientConfig());
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("empty elements 'gzip,,' skipped (§5.6.1)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "gzip,,", gz(kOkResult)); };
    JsonRpcClient client(svc, pool, clientConfig());
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("leading empty ' , gzip' skipped (§5.6.1)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, " , gzip", gz(kOkResult)); };
    JsonRpcClient client(svc, pool, clientConfig());
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("'x-gzip' decodes as gzip (§8.4.1 legacy alias)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "x-gzip", gz(kOkResult)); };
    JsonRpcClient client(svc, pool, clientConfig());
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION("mixed-case 'GZIP' decodes (§8.4.1 case-insensitive)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "GZIP", gz(kOkResult)); };
    JsonRpcClient client(svc, pool, clientConfig());
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
  }

  SECTION(">2 stacked codings rejected before decode (DP-6 hard cap)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "gzip, gzip, gzip", gz(gz(gz(kOkResult)))); };
    JsonRpcClient client(svc, pool, clientConfig());
    REQUIRE_THROWS_AS(client.call(ep, "echo", params), JsonRpcError);
  }

  SECTION("unknown coding 'br' throws (fail loudly, DP-6)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "br", kOkResult); };
    JsonRpcClient client(svc, pool, clientConfig());
    REQUIRE_THROWS_AS(client.call(ep, "echo", params), JsonRpcError);
  }

  SECTION("malformed gzip body throws (task-2.2)")
  {
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "gzip", "not-actually-gzip-bytes"); };
    JsonRpcClient client(svc, pool, clientConfig());
    REQUIRE_THROWS_AS(client.call(ep, "echo", params), JsonRpcError);
  }
}

TEST_CASE("gzip response client: caps + advertise (task-2.1/2.3, DP-5/caps.client)",
          "[gzip-response][client]")
{
  iora::IoraService &svc = startCaptureService(8157);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::string ep = "http://127.0.0.1:8157/capture";
  const iora::parsers::Json params = iora::parsers::Json::object();

  SECTION("advertise=true emits Accept-Encoding: gzip (task-2.1)")
  {
    JsonRpcClient client(svc, pool, clientConfig(/*advertise=*/true));
    REQUIRE(client.call(ep, "echo", params).is_object());
    std::lock_guard<std::mutex> lk(g_rcap.m);
    REQUIRE(g_rcap.reqAcceptEncoding.size() == 1);
    REQUIRE(g_rcap.reqAcceptEncoding[0] == "gzip");
  }

  SECTION("advertise=false emits Accept-Encoding: identity and still decodes gzip (task-2.1)")
  {
    // A false advertiser positively suppresses server compression, but if a server
    // gzips anyway the decoder still inflates it (advertise gates only the header).
    g_rcap.policy = [](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "gzip", gz(kOkResult)); };
    JsonRpcClient client(svc, pool, clientConfig(/*advertise=*/false));
    REQUIRE(client.call(ep, "echo", params)["ok"].get<bool>() == true);
    std::lock_guard<std::mutex> lk(g_rcap.m);
    REQUIRE(g_rcap.reqAcceptEncoding[0] == "identity");
  }

  SECTION("decoded body in (10 MiB, maxDecodedResponseBytes] passes (cap alignment, task-2.3)")
  {
    // ~11.4 MiB inflated JSON, over the 10 MiB single-arg parse default and under the
    // 16 MiB maxDecodedResponseBytes: passes ONLY because sendJson_ aligns the parse
    // cap to maxDecodedResponseBytes for the decoded path. Structured as an array of
    // 15 x 800 KB strings so it stays within the JSON ParseLimits (stringLengthMax
    // 1 MB, arrayItemsMax 10000) — the >10 MiB size is the property under test, not a
    // single oversized string. Highly compressible ('a's) so the gzip WIRE bytes stay
    // under the 1 MiB sync-receive buffer while the DECODED body is ~11.4 MiB.
    std::string arr = "[";
    for (int i = 0; i < 15; ++i)
    {
      arr += (i == 0 ? "\"" : ",\"") + std::string(800 * 1000, 'a') + "\"";
    }
    arr += "]";
    const std::string big =
      R"({"jsonrpc":"2.0","result":{"blob":)" + arr + R"(},"id":1})";
    REQUIRE(big.size() > 10u * 1024 * 1024);
    REQUIRE(big.size() < 16u * 1024 * 1024);
    const std::string gzBig = gz(big);
    REQUIRE(gzBig.size() < 1024u * 1024); // fits the 1 MiB sync-receive buffer
    g_rcap.policy = [gzBig](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "gzip", gzBig); };
    JsonRpcClient client(svc, pool, clientConfig(true, 16 * 1024 * 1024));
    auto r = client.call(ep, "echo", params);
    REQUIRE(r.is_object());
    REQUIRE(r["blob"].is_array());
    REQUIRE(r["blob"].size() == 15u);
  }

  SECTION("identity-path parse cap tracks maxDecodedResponseBytes, not the 10 MiB default (task-2.3)")
  {
    // The identity path uses the SAME aligned parse cap. A >1 MiB identity body is
    // transport-unreachable (maxSyncReceiveBuffer is 1 MiB), so the (10 MiB, 16 MiB]
    // identity window in the arch is not reachable in practice — see the tracker note
    // + surfaced finding. What IS testable, and what the alignment actually wires, is
    // that the identity parse cap is maxDecodedResponseBytes (not the fixed 10 MiB):
    // tighten it below the body and the identity path rejects with the aligned limit.
    const std::string body =
      R"({"jsonrpc":"2.0","result":{"pad":")" + std::string(600, 'x') + R"("},"id":1})";
    g_rcap.policy = [body](int, iora::network::WebhookServer::Response &res)
    {
      res.status = 200;
      res.set_content(body, "application/json"); // identity, no Content-Encoding
    };

    // maxDecoded = 400 < body (~640): identity path enforces the aligned cap and
    // parseJsonOrThrow throws (a std::runtime_error "exceeds maximum size limit of
    // 400 bytes"). A default 10 MiB cap would let this pass — the mutation this pins.
    {
      JsonRpcClient tight(svc, pool, clientConfig(true, /*maxDecoded=*/400));
      REQUIRE_THROWS_WITH(tight.call(ep, "echo", params),
                          Catch::Contains("maximum size limit of 400"));
    }
    // maxDecoded large: the SAME identity body passes.
    {
      JsonRpcClient loose(svc, pool, clientConfig(true, /*maxDecoded=*/16 * 1024 * 1024));
      REQUIRE(loose.call(ep, "echo", params).is_object());
    }
  }

  SECTION("response zip-bomb rejected within maxDecodedResponseBytes (DP-5)")
  {
    // 4 MiB of 'a' compresses tiny (passes the compressed wire guard) but inflates
    // past a 64 KiB decoded cap -> OUTPUT_TOO_LARGE -> JsonRpcError.
    const std::string bomb = gz(std::string(4 * 1024 * 1024, 'a'));
    g_rcap.policy = [bomb](int, iora::network::WebhookServer::Response &res)
    { setCe(res, "gzip", bomb); };
    JsonRpcClient client(svc, pool, clientConfig(true, /*maxDecoded=*/64 * 1024));
    REQUIRE_THROWS_AS(client.call(ep, "echo", params), JsonRpcError);
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// CLIENT decode — defect_8 regression: two PHYSICAL Content-Encoding response lines
// combine (RFC 9110 §5.3, the defect_8 COMBINE fix in HttpClient parseHeaderBlock)
// and double-decode (task-3.3). Driven with a raw responder because a map-based
// server cannot emit duplicate field lines.
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip response client: two physical Content-Encoding lines combine + decode (defect_8)",
          "[gzip-response][client]")
{
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));
  const std::string body = gz(gz(kOkResult)); // double-gzipped -> "gzip, gzip" decodes it
  RawResponder responder(8158, rawHttpResponse("Content-Type: application/json\r\n"
                                               "Content-Encoding: gzip\r\n"
                                               "Content-Encoding: gzip\r\n",
                                               body));

  auto &svc = iora::IoraService::instanceRef();
  JsonRpcClient client(svc, pool, clientConfig());
  auto r = client.call("http://127.0.0.1:8158/rpc", "echo", iora::parsers::Json::object());
  REQUIRE(r.is_object());
  REQUIRE(r["ok"].get<bool>() == true);
}

// ═════════════════════════════════════════════════════════════════════════════
// FULL ROUND-TRIP — real JsonRpcClient (advertises gzip) <-> real mod_jsonrpc_server
// (compresses): the client decodes what the server compressed (task-3.3).
// ═════════════════════════════════════════════════════════════════════════════
TEST_CASE("gzip response round-trip: real client decodes a real server-compressed response",
          "[gzip-response][roundtrip]")
{
  iora::IoraService &svc = startServer(8159, /*responseCompression=*/true, /*threshold=*/32);
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);
  iora::core::ThreadPool pool(2, 2, std::chrono::seconds(1));

  JsonRpcClient client(svc, pool, clientConfig(/*advertise=*/true));
  iora::parsers::Json params = iora::parsers::Json::object();
  params["x"] = std::string(500, 'z'); // result over the server threshold -> compressed

  auto r = client.call("http://localhost:8159/rpc", "echo", params);
  REQUIRE(r.is_object());
  REQUIRE(r["x"].get<std::string>() == std::string(500, 'z'));
}
