// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Client tests for iora::rpc::JsonRpcClient (include/iora/rpc/jsonrpc_client.hpp)
// driven against a programmable in-process HttpServer on an ephemeral loopback
// port. HttpClient is NOT substituted. Authored in phase-6 (tasks 6.1-6.4,
// 6.3a-6.3d) of tracker 2026-07-26-1 — FIRST-EVER real coverage of the client
// send path and the phase-5b HTTP-behaviour fixes (5b.0-5b.4, 5b.6).
//
// ── task-6.1 coverage mapping (old -> new) ──────────────────────────────────
// The deleted module test src/modules/connectors/jsonrpc_client/tests/
// iora_test_mod_jsonrpc_client_server_real.cpp had FIVE TEST_CASEs. Every
// client operation in TEST_CASEs 1, 3 and 4 was wrapped
//     try { op(); REQUIRE(...); } catch (const std::exception&) { print "…failed"; }
// so ANY throw from the operation under test was swallowed and the case passed
// regardless — VACUOUS-BY-CATCH, zero enforced client coverage. TEST_CASE 2 was
// server-only. ONLY TEST_CASE 5 ("HTTP Client Connection Timeout Test", lines
// 751-852) was genuinely enforced: (a) a connect against a closed port fails in
// bounded time, and (b) an invalid URL is rejected. Those two are re-expressed
// here (task-6.4 connection-refused via testnet::RefusingEndpoint; invalid-URL
// rejection below). Everything else the old file merely enumerated — call,
// notify, callAsync+result, resetStats, purgeIdle, getStats (10 fields),
// callBatch, callBatchAsync — is given first-ever ENFORCED coverage here.
// EXPECT NEW FAILURES to be real defects, not test bugs.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/rpc/jsonrpc_client.hpp"

#include "jsonrpc_test_ids.hpp" // testrpc::requestId (light id-extraction header, L9/S-4)

#include "iora/core/thread_pool.hpp"
#include "iora/network/http_server.hpp"
#include "iora/parsers/json.hpp"
#include "iora/util/gzip.hpp"

// testnet::getFreePortTCP / RefusingEndpoint use Catch2 REQUIRE at construction,
// so this include MUST follow catch2 above.
#include "iora_test_net_utils.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

using iora::parsers::Json;
using iora::rpc::BatchItem;
using iora::rpc::Config;
using iora::rpc::JsonRpcClient;
using iora::rpc::JsonRpcError;
using iora::rpc::PoolExhaustedError;
using iora::rpc::RemoteError;
using namespace std::chrono_literals;

namespace
{

// ── task-6.2: programmable in-process HttpServer test server ────────────────
// A POST-only server on an ephemeral loopback port whose per-request reply is a
// caller-installed Responder (default: echo the request id with a success
// envelope). Records the request count and the last request's body / Content-Type
// / Content-Encoding so the wire-level assertions (fix_5) can read them.
// HttpClient is NOT subclassed anywhere (LD-7).
class ProgrammableServer
{
public:
  using Request = iora::network::HttpServer::Request;
  using Response = iora::network::HttpServer::Response;
  using Responder = std::function<void(const Request &, Response &)>;

  ProgrammableServer()
      : _port(testnet::getFreePortTCP()), _server("127.0.0.1", static_cast<int>(_port))
  {
    setResponder(successResult(Json("ok")));
    _server.onPost("/rpc",
                   [this](const Request &req, Response &res)
                   {
                     Responder r;
                     {
                       std::lock_guard<std::mutex> lk(_m);
                       ++_count;
                       _lastBody = req.body;
                       _lastContentType =
                         req.has_header("Content-Type") ? req.get_header_value("Content-Type") : "";
                       _lastContentEncoding = req.has_header("Content-Encoding")
                                                ? req.get_header_value("Content-Encoding")
                                                : "";
                       r = _responder; // copy-then-invoke: never hold the lock across the handler
                     }
                     r(req, res);
                   });
    _server.start();
    std::this_thread::sleep_for(150ms); // let the listener settle
  }

  ~ProgrammableServer() { _server.stop(); }

  ProgrammableServer(const ProgrammableServer &) = delete;
  ProgrammableServer &operator=(const ProgrammableServer &) = delete;

  std::string url() const { return "http://127.0.0.1:" + std::to_string(_port) + "/rpc"; }

  void setResponder(Responder r)
  {
    std::lock_guard<std::mutex> lk(_m);
    _responder = std::move(r);
  }

  int requestCount()
  {
    std::lock_guard<std::mutex> lk(_m);
    return _count;
  }
  std::string lastBody()
  {
    std::lock_guard<std::mutex> lk(_m);
    return _lastBody;
  }
  std::string lastContentType()
  {
    std::lock_guard<std::mutex> lk(_m);
    return _lastContentType;
  }
  std::string lastContentEncoding()
  {
    std::lock_guard<std::mutex> lk(_m);
    return _lastContentEncoding;
  }

  // ── responder factories ──────────────────────────────────────────────────
  // Slice-B review L9: id extraction is the shared testrpc::requestId; only the
  // envelope builders below stay per-fixture.
  static Json idOf(const Request &req)
  {
    return testrpc::requestId(req.body);
  }

  /// Success envelope echoing the request id with a fixed result.
  static Responder successResult(Json result)
  {
    return [result](const Request &req, Response &res)
    {
      Json env;
      env["jsonrpc"] = "2.0";
      env["result"] = result;
      env["id"] = idOf(req);
      res.set_content(env.dump(), "application/json");
    };
  }

  /// JSON-RPC error envelope at the given HTTP status, echoing the request id.
  static Responder errorEnvelope(int status, int code, std::string message)
  {
    return [status, code, message](const Request &req, Response &res)
    {
      Json err;
      err["code"] = code;
      err["message"] = message;
      Json env;
      env["jsonrpc"] = "2.0";
      env["error"] = err;
      env["id"] = idOf(req);
      res.status = status;
      res.set_content(env.dump(), "application/json");
    };
  }

  /// A raw body at a raw status (for garbage / non-conformant / non-JSON-RPC).
  static Responder rawBody(int status, std::string body, std::string contentType = "application/json")
  {
    return [status, body, contentType](const Request &, Response &res)
    {
      res.status = status;
      res.set_content(body, contentType);
    };
  }

  /// A bodyless status (204, or a 200 with no body).
  static Responder emptyStatus(int status)
  {
    return [status](const Request &, Response &res) { res.status = status; };
  }

private:
  std::mutex _m;
  std::uint16_t _port;
  int _count = 0;
  std::string _lastBody;
  std::string _lastContentType;
  std::string _lastContentEncoding;
  Responder _responder;
  iora::network::HttpServer _server; // declared LAST -> destroyed FIRST
};

// ── task-6.3e: one-shot request latch ────────────────────────────────────────
// A responder can PARK a request in-flight (arriveAndWait) so its connection
// stays leased while a second call races the saturated pool. Every wait is
// deadline-bounded so a wedged test fails rather than hangs.
class RequestLatch
{
public:
  /// Called from the server thread: signal arrival, then block until released.
  void arriveAndWait()
  {
    std::unique_lock<std::mutex> lk(_m);
    _arrived = true;
    _cv.notify_all();
    _cv.wait_for(lk, 10s, [&] { return _released; });
  }
  /// Called from the test thread: block until a request has parked.
  bool waitUntilArrived()
  {
    std::unique_lock<std::mutex> lk(_m);
    return _cv.wait_for(lk, 5s, [&] { return _arrived; });
  }
  void release()
  {
    std::lock_guard<std::mutex> lk(_m);
    _released = true;
    _cv.notify_all();
  }

private:
  std::mutex _m;
  std::condition_variable _cv;
  bool _arrived = false;
  bool _released = false;
};

// A success responder that parks on `latch` before replying, echoing the id.
ProgrammableServer::Responder latchedSuccess(RequestLatch &latch, Json result)
{
  return [&latch, result](const ProgrammableServer::Request &req,
                          ProgrammableServer::Response &res)
  {
    latch.arriveAndWait();
    Json env;
    env["jsonrpc"] = "2.0";
    env["result"] = result;
    env["id"] = ProgrammableServer::idOf(req);
    res.set_content(env.dump(), "application/json");
  };
}

// A success responder that INFLATES a gzip request body (raw HttpServer does not
// auto-decompress), then echoes the id — the server counterpart of client
// request compression.
ProgrammableServer::Responder inflatingEcho(Json result)
{
  return [result](const ProgrammableServer::Request &req, ProgrammableServer::Response &res)
  {
    std::string body = req.body;
    if (req.has_header("Content-Encoding") &&
        iora::core::StringUtils::iequals(req.get_header_value("Content-Encoding"), "gzip"))
    {
      auto r = iora::util::Gzip::decompress(body, 1u << 20);
      if (r.isOk())
      {
        body = std::move(r).value();
      }
    }
    Json id(nullptr);
    const auto pr = Json::parse(body, iora::parsers::ParseLimits{});
    if (pr.ok && pr.value.is_object() && pr.value.contains("id"))
    {
      id = pr.value["id"];
    }
    Json env;
    env["jsonrpc"] = "2.0";
    env["result"] = result;
    env["id"] = id;
    res.set_content(env.dump(), "application/json");
  };
}

// A responder that returns a gzip-COMPRESSED success envelope (Content-Encoding:
// gzip), for the client response-inflate path.
ProgrammableServer::Responder gzipSuccess(Json result)
{
  return [result](const ProgrammableServer::Request &req, ProgrammableServer::Response &res)
  {
    Json env;
    env["jsonrpc"] = "2.0";
    env["result"] = result;
    env["id"] = ProgrammableServer::idOf(req);
    res.set_header("Content-Encoding", "gzip");
    res.set_content(iora::util::Gzip::compress(env.dump()), "application/json");
  };
}

// A fast client config: short timeouts and tiny retry backoff so the retry and
// refused-connection cases finish in milliseconds.
Config fastConfig()
{
  Config cfg;
  cfg.requestTimeout = 2s;
  cfg.connectionTimeout = 2s;
  cfg.maxRetries = 3;
  cfg.initialRetryDelay = 1ms;
  cfg.maxRetryDelay = 2ms;
  return cfg;
}

const std::vector<std::pair<std::string, std::string>> kNoHeaders{};

} // namespace

// ── task-6.3a: happy path + error envelope + malformed / non-JSON-RPC + id ───
TEST_CASE("jsonrpc client: happy-path call round trip", "[jsonrpc_client][happy]")
{
  ProgrammableServer server;
  server.setResponder(ProgrammableServer::successResult(Json("pong")));
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  Json result = client.call(server.url(), "ping", Json("hi"), kNoHeaders);
  REQUIRE(result.is_string());
  REQUIRE(result.get<std::string>() == "pong");
  REQUIRE(server.requestCount() == 1);

  auto stats = client.getStats();
  REQUIRE(stats.totalRequests == 1);
  REQUIRE(stats.successfulRequests == 1);
  REQUIRE(stats.failedRequests == 0);
}

TEST_CASE("jsonrpc client: error envelope surfaces as RemoteError (5b.2)",
          "[jsonrpc_client][error-envelope]")
{
  ProgrammableServer server;
  // A JSON-RPC error at HTTP 200: parseResponseOrThrow_ must throw RemoteError.
  server.setResponder(ProgrammableServer::errorEnvelope(200, -32601, "Method not found"));
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  bool threw = false;
  try
  {
    client.call(server.url(), "nope", Json(nullptr), kNoHeaders);
  }
  catch (const RemoteError &e)
  {
    threw = true;
    REQUIRE(e.code() == -32601);
    REQUIRE(e.message() == "Method not found");
  }
  REQUIRE(threw);
  auto stats = client.getStats();
  REQUIRE(stats.failedRequests == 1);
  REQUIRE(stats.successfulRequests == 0);
}

TEST_CASE("jsonrpc client: malformed and non-JSON-RPC 200 bodies throw (5b.2)",
          "[jsonrpc_client][malformed]")
{
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  SECTION("garbage body -> throw")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::rawBody(200, "{not json"));
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), std::exception);
  }
  SECTION("a JSON 200 that is not a JSON-RPC response -> JsonRpcError")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::rawBody(200, R"({"foo":1})"));
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }
  SECTION("a bare scalar 200 body -> JsonRpcError")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::rawBody(200, "123"));
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }
  SECTION("a 200 carrying BOTH result and error -> JsonRpcError")
  {
    ProgrammableServer server;
    server.setResponder(
      ProgrammableServer::rawBody(200, R"({"jsonrpc":"2.0","result":1,"error":{"code":1,"message":"x"},"id":0})"));
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }
}

TEST_CASE("jsonrpc client: single-call id correlation (5b.3)", "[jsonrpc_client][id-correlation]")
{
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  SECTION("a mismatched non-null id throws rather than returning another call's result")
  {
    ProgrammableServer server;
    server.setResponder(
      [](const ProgrammableServer::Request &, ProgrammableServer::Response &res)
      {
        // A well-formed success envelope, but with the WRONG id (never any client id).
        res.set_content(R"({"jsonrpc":"2.0","result":"stray","id":999999})", "application/json");
      });
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }
  SECTION("a null id on a non-error response is a correlation failure")
  {
    ProgrammableServer server;
    server.setResponder(
      [](const ProgrammableServer::Request &, ProgrammableServer::Response &res)
      { res.set_content(R"({"jsonrpc":"2.0","result":"x","id":null})", "application/json"); });
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }
  SECTION("a string id can never match a numeric request id")
  {
    ProgrammableServer server;
    server.setResponder(
      [](const ProgrammableServer::Request &, ProgrammableServer::Response &res)
      { res.set_content(R"({"jsonrpc":"2.0","result":"x","id":"abc"})", "application/json"); });
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }
  SECTION("id:null on an ERROR response is EXEMPT (B-web L-2) -> surfaces the RemoteError")
  {
    ProgrammableServer server;
    server.setResponder(
      [](const ProgrammableServer::Request &, ProgrammableServer::Response &res) {
        res.set_content(
          R"({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":null})",
          "application/json");
      });
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), RemoteError);
  }
}

TEST_CASE("jsonrpc client: non-2xx envelope surfacing is lenient (5b.4)",
          "[jsonrpc_client][non-2xx]")
{
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  SECTION("a 415 carrying a conformant envelope -> RemoteError, not runtime_error")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::errorEnvelope(415, -32015, "Unsupported Media Type"));
    bool remote = false;
    try
    {
      client.call(server.url(), "m", Json(nullptr), kNoHeaders);
    }
    catch (const RemoteError &e)
    {
      remote = true;
      REQUIRE(e.code() == -32015);
      REQUIRE(e.message() == "Unsupported Media Type");
    }
    REQUIRE(remote);
  }
  SECTION("M5: a 429 with a conformant envelope -> RemoteError, exactly one send (not retried)")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::errorEnvelope(429, -32000, "Too Many Requests"));
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), RemoteError);
    REQUIRE(server.requestCount() == 1);
  }
  SECTION("M5: a 408 with a conformant envelope -> RemoteError, exactly one send (not retried)")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::errorEnvelope(408, -32000, "Request Timeout"));
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), RemoteError);
    REQUIRE(server.requestCount() == 1);
  }
  SECTION("M7: a 502 with a NON-conformant JSON body -> HTTP-status error, not JsonRpcError")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::rawBody(502, R"({"error":"gateway timeout"})"));
    // A conformant JSON-RPC error is a RemoteError (subclass of JsonRpcError); a
    // non-conformant body must fall back to the plain HTTP-status std::runtime_error.
    bool sawJsonRpc = false;
    bool threw = false;
    try
    {
      client.call(server.url(), "m", Json(nullptr), kNoHeaders);
    }
    catch (const JsonRpcError &)
    {
      sawJsonRpc = true;
      threw = true;
    }
    catch (const std::exception &)
    {
      threw = true;
    }
    REQUIRE(threw);
    REQUIRE_FALSE(sawJsonRpc);
    REQUIRE(server.requestCount() == 1);
  }
  SECTION("a non-2xx with no body -> HTTP-status error")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::emptyStatus(500));
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), std::runtime_error);
    REQUIRE(server.requestCount() == 1);
  }
}

TEST_CASE("jsonrpc client: M6 call() against a 204 / 200-empty throws",
          "[jsonrpc_client][no-result]")
{
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  // Slice-B review L4 (M6 diagnostic): the throw is now a SEMANTIC JsonRpcError
  // ("...no result body for a call...") raised in sendJson_ step (3b), not the
  // opaque parse-error from step (4)'s Json::parse(""). Assert the specific type.
  SECTION("call() against a 204 throws JsonRpcError (a success Response MUST carry a result, §5)")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::emptyStatus(204));
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }
  SECTION("call() against a 200-with-empty-body throws JsonRpcError")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::emptyStatus(200));
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }
}

// NOTE (Slice-B review L5): these cases assert Content-Type at the HttpServer
// header-map VALUE level (lastContentType()). HttpServer last-wins-collapses a
// duplicate single-valued request header before the handler runs, so the
// BYTE-LEVEL "exactly one Content-Type field-line on the wire" guarantee is
// asserted in iora_test_jsonrpc_client_pool.cpp (task-7.4: countFieldLinesNamed(
// reqs[0], "Content-Type") == 1 + hasFieldLine "application/json-rpc") against the
// raw captured request. Together with mergeHeaders_'s one-key canonicalization,
// the wire-line uniqueness (RFC 9112 §5) is covered; it is deliberately not
// re-asserted here (this ProgrammableServer parses into a map).
TEST_CASE("jsonrpc client: caller Content-Type reaches the wire (5b.6 / fix_5)",
          "[jsonrpc_client][content-type]")
{
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  SECTION("a caller-supplied application/json-rpc reaches the server (identity path)")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::successResult(Json("ok")));
    std::vector<std::pair<std::string, std::string>> headers{
      {"Content-Type", "application/json-rpc"}};
    client.call(server.url(), "m", Json(nullptr), headers);
    REQUIRE(server.lastContentType() == "application/json-rpc");
  }
  SECTION("a caller supplying no Content-Type gets application/json")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::successResult(Json("ok")));
    client.call(server.url(), "m", Json(nullptr), kNoHeaders);
    REQUIRE(server.lastContentType() == "application/json");
  }
}

// ── task-6.3b: retry / attempt counting ─────────────────────────────────────
TEST_CASE("jsonrpc client: a received non-2xx is NOT retried (possibly-sent)",
          "[jsonrpc_client][retry]")
{
  ProgrammableServer server;
  server.setResponder(ProgrammableServer::errorEnvelope(500, -32603, "Internal error"));
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), RemoteError);
  REQUIRE(server.requestCount() == 1); // possibly-sent -> exactly one send
  auto stats = client.getStats();
  REQUIRE(stats.retriedRequests == 0);
}

TEST_CASE("jsonrpc client: a provably-not-sent refusal IS retried to the attempt cap",
          "[jsonrpc_client][retry]")
{
  testnet::RefusingEndpoint refusing; // bound-but-not-listening -> ECONNREFUSED
  iora::core::ThreadPool pool(2, 4, 2s);
  Config cfg = fastConfig();
  cfg.maxRetries = 3;
  JsonRpcClient client(pool, cfg);

  const std::string url = "http://127.0.0.1:" + std::to_string(refusing.port()) + "/rpc";
  REQUIRE_THROWS_AS(client.call(url, "m", Json(nullptr), kNoHeaders), std::exception);
  auto stats = client.getStats();
  // sendJsonWithRetries_ increments retriedRequests once per retry; with
  // maxRetries=3 the loop retries 3 times (attempts 1,2,3) then throws == 4 sends.
  REQUIRE(stats.retriedRequests == 3);
}

// ── task-6.3c: notify + batch ────────────────────────────────────────────────
TEST_CASE("jsonrpc client: notify against a real 204 succeeds without parsing (5b.1)",
          "[jsonrpc_client][notify]")
{
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  SECTION("204 -> success, handler invoked exactly once, no retry")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::emptyStatus(204));
    REQUIRE_NOTHROW(client.notify(server.url(), "evt", Json("x"), kNoHeaders));
    REQUIRE(server.requestCount() == 1);
    auto stats = client.getStats();
    REQUIRE(stats.retriedRequests == 0);
    REQUIRE(stats.notificationRequests == 1);
    REQUIRE(stats.successfulRequests == 1);
  }
  SECTION("200-with-empty-body -> success without parsing")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::emptyStatus(200));
    REQUIRE_NOTHROW(client.notify(server.url(), "evt", Json("x"), kNoHeaders));
    REQUIRE(server.requestCount() == 1);
  }
}

TEST_CASE("jsonrpc client: batch success and mixed result/error", "[jsonrpc_client][batch]")
{
  ProgrammableServer server;
  // Reply with an array: echo each request id, item 1 -> result, item 2 -> error.
  server.setResponder(
    [](const ProgrammableServer::Request &req, ProgrammableServer::Response &res)
    {
      const auto pr = Json::parse(req.body, iora::parsers::ParseLimits{});
      Json arr = Json::array();
      if (pr.ok && pr.value.is_array())
      {
        for (const auto &item : pr.value)
        {
          if (!item.contains("id"))
          {
            continue; // a notification gets no response item
          }
          Json env;
          env["jsonrpc"] = "2.0";
          env["id"] = item["id"];
          if (item["method"].get<std::string>() == "bad")
          {
            Json err;
            err["code"] = -32000;
            err["message"] = "boom";
            env["error"] = err;
          }
          else
          {
            env["result"] = Json("okitem");
          }
          arr.push_back(env);
        }
      }
      res.set_content(arr.dump(), "application/json");
    });
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  std::vector<BatchItem> items;
  items.emplace_back("good", Json(nullptr), 1u);
  items.emplace_back("bad", Json(nullptr), 2u);

  // callBatch surfaces per-item outcomes: a mixed batch throws when a member is an
  // error envelope (the batch parser rethrows the first error item).
  REQUIRE_THROWS_AS(client.callBatch(server.url(), items, kNoHeaders), RemoteError);

  // An all-good batch returns per-item results.
  std::vector<BatchItem> allGood;
  allGood.emplace_back("good", Json(nullptr), 10u);
  allGood.emplace_back("good", Json(nullptr), 11u);
  auto results = client.callBatch(server.url(), allGood, kNoHeaders);
  REQUIRE(results.size() == 2);
  REQUIRE(results[0].get<std::string>() == "okitem");
  REQUIRE(results[1].get<std::string>() == "okitem");
}

TEST_CASE("jsonrpc client: a batch item that is not a valid JSON-RPC response throws (5b.2)",
          "[jsonrpc_client][batch]")
{
  ProgrammableServer server;
  server.setResponder(
    [](const ProgrammableServer::Request &req, ProgrammableServer::Response &res)
    {
      const auto pr = Json::parse(req.body, iora::parsers::ParseLimits{});
      Json arr = Json::array();
      if (pr.ok && pr.value.is_array())
      {
        for (const auto &item : pr.value)
        {
          // A response item missing jsonrpc + result/error, but with a matching id.
          Json bad;
          bad["id"] = item["id"];
          bad["garbage"] = true;
          arr.push_back(bad);
        }
      }
      res.set_content(arr.dump(), "application/json");
    });
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  std::vector<BatchItem> items;
  items.emplace_back("m", Json(nullptr), 1u);
  REQUIRE_THROWS_AS(client.callBatch(server.url(), items, kNoHeaders), JsonRpcError);
}

// Slice-B review L2: an ALL-notification batch is reachable via the public API
// (BatchItem's 2-arg ctor omits the id). Per JSON-RPC 2.0 §6 the server returns
// nothing (a 2xx-empty), and the client must succeed with one null per item — NOT
// throw trying to parse the empty body.
TEST_CASE("jsonrpc client: an all-notification batch succeeds against a 2xx-empty (L2)",
          "[jsonrpc_client][batch]")
{
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  SECTION("204 for an all-notification batch -> vector of nulls, no throw")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::emptyStatus(204));
    std::vector<BatchItem> items;
    items.emplace_back("evt1", Json("a")); // no id -> notification
    items.emplace_back("evt2", Json("b")); // no id -> notification
    std::vector<Json> results;
    REQUIRE_NOTHROW(results = client.callBatch(server.url(), items, kNoHeaders));
    REQUIRE(results.size() == 2);
    REQUIRE(results[0].is_null());
    REQUIRE(results[1].is_null());
    REQUIRE(server.requestCount() == 1);
  }
  SECTION("200-with-empty-body for an all-notification batch also succeeds")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::emptyStatus(200));
    std::vector<BatchItem> items;
    items.emplace_back("evt", Json(nullptr));
    std::vector<Json> results;
    REQUIRE_NOTHROW(results = client.callBatch(server.url(), items, kNoHeaders));
    REQUIRE(results.size() == 1);
    REQUIRE(results[0].is_null());
  }
  // Slice-B review W-1/W-2 (DD-notify-ignores-2xx-body): a NoResultExpected request's
  // outcome is the HTTP status ALONE (§4.1). A non-conformant server that sends a 2xx
  // WITH a body must NOT make it throw or silently discard-after-parse — the body is
  // ignored.
  SECTION("W-1: an all-notification batch + a 2xx JSON error-body still succeeds (body ignored)")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::rawBody(
      200, R"({"jsonrpc":"2.0","error":{"code":-32600,"message":"stray"},"id":null})"));
    std::vector<BatchItem> items;
    items.emplace_back("evt1", Json("a"));
    items.emplace_back("evt2", Json("b"));
    std::vector<Json> results;
    REQUIRE_NOTHROW(results = client.callBatch(server.url(), items, kNoHeaders));
    REQUIRE(results.size() == 2);
    REQUIRE(results[0].is_null());
    REQUIRE(results[1].is_null());
  }
  SECTION("W-2: notify() against a 2xx with a NON-JSON body still succeeds (body ignored)")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::rawBody(200, "this is not json at all"));
    REQUIRE_NOTHROW(client.notify(server.url(), "evt", Json("x"), kNoHeaders));
    REQUIRE(client.getStats().successfulRequests == 1);
    REQUIRE(client.getStats().failedRequests == 0);
  }
}

// Slice-B review L1: a batch response item carrying a NON-integer id must surface
// a JsonRpcError (the documented client error base), not an opaque Json type error
// (bad_variant_access). Mirrors the single-call correlateIdOrThrow_ type discipline.
TEST_CASE("jsonrpc client: a batch response with a non-integer id throws JsonRpcError (L1)",
          "[jsonrpc_client][batch]")
{
  ProgrammableServer server;
  server.setResponder(
    [](const ProgrammableServer::Request &, ProgrammableServer::Response &res)
    {
      // A well-formed success item, but with a STRING id (the client only sends
      // numeric ids, so this is a non-correlatable, non-conformant response).
      res.set_content(R"([{"jsonrpc":"2.0","result":{},"id":"not-a-number"}])", "application/json");
    });
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  std::vector<BatchItem> items;
  items.emplace_back("m", Json(nullptr), 1u);
  REQUIRE_THROWS_AS(client.callBatch(server.url(), items, kNoHeaders), JsonRpcError);
}

// ── task-6.3d: both callAsync overloads ──────────────────────────────────────
TEST_CASE("jsonrpc client: callAsync future overload resolves", "[jsonrpc_client][async]")
{
  ProgrammableServer server;
  server.setResponder(ProgrammableServer::successResult(Json("async-ok")));
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  auto fut = client.callAsync(server.url(), "m", Json(nullptr), kNoHeaders);
  Json result = fut.get();
  REQUIRE(result.get<std::string>() == "async-ok");
}

TEST_CASE("jsonrpc client: callAsync callback overload invokes onSuccess / onError",
          "[jsonrpc_client][async]")
{
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  SECTION("onSuccess fires with the result")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::successResult(Json("cb-ok")));
    std::promise<Json> done;
    auto fut = done.get_future();
    client.callAsync(server.url(), "m", Json(nullptr), kNoHeaders,
                     [&done](Json r) { done.set_value(std::move(r)); },
                     [&done](std::exception_ptr) { done.set_value(Json("ERR")); });
    REQUIRE(fut.wait_for(5s) == std::future_status::ready);
    REQUIRE(fut.get().get<std::string>() == "cb-ok");
  }
  SECTION("onError fires on a JSON-RPC error envelope")
  {
    ProgrammableServer server;
    server.setResponder(ProgrammableServer::errorEnvelope(200, -32601, "nope"));
    std::promise<bool> done;
    auto fut = done.get_future();
    client.callAsync(server.url(), "m", Json(nullptr), kNoHeaders,
                     [&done](Json) { done.set_value(false); },
                     [&done](std::exception_ptr) { done.set_value(true); });
    REQUIRE(fut.wait_for(5s) == std::future_status::ready);
    REQUIRE(fut.get() == true);
  }
}

// ── task-6.3e: pool exhaustion (LATCHED) + purgeIdle + stats + gzip ──────────
// Pool exhaustion is LATCHED, not timing-based. Per arch DD-pool-exhaustion-is-
// poolexhaustederror-not-leasetimeout-2026-09-09 (human Option A, verified
// empirically): the JsonRpcClient's OWN pooling refuses BOTH saturation modes
// with PoolExhaustedError, thrown immediately with no wait —
// network::HttpLeaseAcquireTimeoutError is NOT reachable through it (one wrapper
// is marked inUse per in-flight request). The two modes differ by trigger/message.
TEST_CASE("jsonrpc client: single-endpoint cap-1 saturation -> PoolExhaustedError (LATCHED)",
          "[jsonrpc_client][pool-exhaustion]")
{
  RequestLatch latch;
  ProgrammableServer server;
  server.setResponder(latchedSuccess(latch, Json("held")));

  Config cfg = fastConfig();
  cfg.maxConnectionsPerEndpoint = 1; // one wrapper -> the second concurrent call is refused
  cfg.requestTimeout = 8s;           // let the first call sit latched, don't time it out
  cfg.connectionTimeout = 8s;
  cfg.maxRetries = 0;
  iora::core::ThreadPool pool(4, 8, 5s);
  JsonRpcClient client(pool, cfg);

  // Park the one connection in-flight on a background thread.
  std::thread holder(
    [&] {
      try { client.call(server.url(), "held", Json(nullptr), kNoHeaders); }
      catch (...) {}
    });
  REQUIRE(latch.waitUntilArrived());

  // The pool is saturated (cap 1, the one wrapper leased): a second call is
  // refused IMMEDIATELY with PoolExhaustedError, distinguished by its message.
  bool threw = false;
  try
  {
    client.call(server.url(), "second", Json(nullptr), kNoHeaders);
  }
  catch (const PoolExhaustedError &e)
  {
    threw = true;
    REQUIRE(std::string(e.what()).find("No available HTTP connections") != std::string::npos);
  }
  REQUIRE(threw);
  // Mutation-test: the stat fires only on the refusal (0 if the pool were not saturated).
  REQUIRE(client.getStats().poolExhaustions == 1);

  latch.release();
  holder.join();
}

TEST_CASE("jsonrpc client: maxEndpointPools cap -> PoolExhaustedError (distinct trigger)",
          "[jsonrpc_client][pool-exhaustion]")
{
  RequestLatch latch;
  ProgrammableServer serverA; // pool A, held in-flight -> non-idle, cannot be evicted
  ProgrammableServer serverB; // a distinct endpoint whose new pool overshoots the cap
  serverA.setResponder(latchedSuccess(latch, Json("A")));
  serverB.setResponder(ProgrammableServer::successResult(Json("B")));

  Config cfg = fastConfig();
  cfg.maxEndpointPools = 1;          // one pool at a time
  cfg.maxConnectionsPerEndpoint = 1;
  cfg.requestTimeout = 8s;
  cfg.connectionTimeout = 8s;
  cfg.maxRetries = 0;
  iora::core::ThreadPool pool(4, 8, 5s);
  JsonRpcClient client(pool, cfg);

  std::thread holder(
    [&] {
      try { client.call(serverA.url(), "A", Json(nullptr), kNoHeaders); }
      catch (...) {}
    });
  REQUIRE(latch.waitUntilArrived());

  // Endpoint B needs a new pool, but the single slot is held by the non-idle
  // pool A, which cannot be LRU-evicted -> the cap is enforced with a throw whose
  // message names THIS trigger, not the per-endpoint one above.
  bool threw = false;
  try
  {
    client.call(serverB.url(), "B", Json(nullptr), kNoHeaders);
  }
  catch (const PoolExhaustedError &e)
  {
    threw = true;
    REQUIRE(std::string(e.what()).find("Max endpoint pools reached") != std::string::npos);
  }
  REQUIRE(threw);
  REQUIRE(client.getStats().poolExhaustions == 1);

  latch.release();
  holder.join();
}

TEST_CASE("jsonrpc client: purgeIdle evicts a connection idle past idleTimeout",
          "[jsonrpc_client][purge]")
{
  ProgrammableServer server;
  server.setResponder(ProgrammableServer::successResult(Json("ok")));

  Config cfg = fastConfig();
  cfg.idleTimeout = 200ms; // wrapper OBJECT idle window
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, cfg);

  // One call creates and then releases one pooled wrapper (now idle).
  client.call(server.url(), "m", Json(nullptr), kNoHeaders);
  client.resetStats(); // isolate the eviction count from any acquire-path reclaim

  // Mutation-test control: not yet idle -> purgeIdle evicts nothing.
  REQUIRE(client.purgeIdle() == 0);
  REQUIRE(client.getStats().connectionsEvicted == 0);

  std::this_thread::sleep_for(350ms); // now past idleTimeout
  REQUIRE(client.purgeIdle() == 1);
  REQUIRE(client.getStats().connectionsEvicted == 1);
}

TEST_CASE("jsonrpc client: getStats reflects activity and resetStats zeroes it",
          "[jsonrpc_client][stats]")
{
  ProgrammableServer server;
  server.setResponder(ProgrammableServer::successResult(Json("ok")));
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  client.call(server.url(), "m", Json(nullptr), kNoHeaders);
  client.call(server.url(), "m", Json(nullptr), kNoHeaders);
  auto before = client.getStats();
  REQUIRE(before.totalRequests == 2);
  REQUIRE(before.successfulRequests == 2);

  client.resetStats();
  auto after = client.getStats();
  REQUIRE(after.totalRequests == 0);
  REQUIRE(after.successfulRequests == 0);
  REQUIRE(after.failedRequests == 0);
}

// ── task-6.3e: Consumer C gzip round-trip ────────────────────────────────────
TEST_CASE("jsonrpc client: gzip request round-trip (enableRequestCompression)",
          "[jsonrpc_client][gzip][request]")
{
  ProgrammableServer server;
  server.setResponder(inflatingEcho(Json("pong")));

  Config cfg = fastConfig();
  cfg.enableRequestCompression = true;
  cfg.compressionThreshold = 1; // force compression of any non-trivial body
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, cfg);

  Json result = client.call(server.url(), "m", Json("some payload that exceeds the threshold"),
                            kNoHeaders);
  REQUIRE(result.get<std::string>() == "pong");
  // The request reached the wire gzip-encoded and the server inflated it.
  REQUIRE(server.lastContentEncoding() == "gzip");
}

TEST_CASE("jsonrpc client: gzip response is inflated (advertiseAcceptEncoding)",
          "[jsonrpc_client][gzip][response]")
{
  ProgrammableServer server;
  server.setResponder(gzipSuccess(Json("inflated")));
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig()); // advertiseAcceptEncoding defaults true

  Json result = client.call(server.url(), "m", Json(nullptr), kNoHeaders);
  REQUIRE(result.get<std::string>() == "inflated");
}

TEST_CASE("jsonrpc client: an unsupported response Content-Encoding throws",
          "[jsonrpc_client][gzip][response]")
{
  ProgrammableServer server;
  server.setResponder(
    [](const ProgrammableServer::Request &, ProgrammableServer::Response &res)
    {
      res.set_header("Content-Encoding", "br"); // brotli is not decodable client-side
      res.set_content(R"({"jsonrpc":"2.0","result":"x","id":0})", "application/json");
    });
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, fastConfig());

  REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
}

TEST_CASE("jsonrpc client: a 415 on a compressed request latches identity and re-sends ONCE",
          "[jsonrpc_client][gzip][latch]")
{
  ProgrammableServer server;
  // Reject the gzip-encoded request with 415; accept the identity re-send.
  server.setResponder(
    [](const ProgrammableServer::Request &req, ProgrammableServer::Response &res)
    {
      if (req.has_header("Content-Encoding") &&
          iora::core::StringUtils::iequals(req.get_header_value("Content-Encoding"), "gzip"))
      {
        res.status = 415; // refuse the coding
        return;
      }
      Json env;
      env["jsonrpc"] = "2.0";
      env["result"] = Json("identity-ok");
      const auto pr = Json::parse(req.body, iora::parsers::ParseLimits{});
      env["id"] = (pr.ok && pr.value.is_object() && pr.value.contains("id")) ? pr.value["id"]
                                                                             : Json(nullptr);
      res.set_content(env.dump(), "application/json");
    });

  Config cfg = fastConfig();
  cfg.enableRequestCompression = true;
  cfg.compressionThreshold = 1;
  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, cfg);

  Json result = client.call(server.url(), "m", Json("a body over the threshold"), kNoHeaders);
  REQUIRE(result.get<std::string>() == "identity-ok");
  REQUIRE(server.requestCount() == 2);            // compressed attempt + identity re-send
  REQUIRE(server.lastContentEncoding().empty());  // the accepted re-send was identity
}

// ── task-6.3e: client response-gzip security ─────────────────────────────────
TEST_CASE("jsonrpc client: response-gzip security limits", "[jsonrpc_client][gzip][security]")
{
  SECTION("a decompression bomb is rejected as OUTPUT_TOO_LARGE before parse")
  {
    ProgrammableServer server;
    // A small gzip that inflates far past maxDecodedResponseBytes.
    const std::string bomb = iora::util::Gzip::compress(std::string(64 * 1024, 'A'));
    server.setResponder(
      [bomb](const ProgrammableServer::Request &, ProgrammableServer::Response &res)
      {
        res.set_header("Content-Encoding", "gzip");
        res.set_content(bomb, "application/json");
      });
    Config cfg = fastConfig();
    cfg.maxDecodedResponseBytes = 1024; // cap well below the inflated size
    iora::core::ThreadPool pool(2, 4, 2s);
    JsonRpcClient client(pool, cfg);

    bool threw = false;
    try
    {
      client.call(server.url(), "m", Json(nullptr), kNoHeaders);
    }
    catch (const JsonRpcError &e)
    {
      threw = true;
      REQUIRE(std::string(e.what()).find("maxDecodedResponseBytes") != std::string::npos);
    }
    REQUIRE(threw);
  }

  SECTION("a response stacking more than 2 codings is rejected")
  {
    ProgrammableServer server;
    server.setResponder(
      [](const ProgrammableServer::Request &, ProgrammableServer::Response &res)
      {
        res.set_header("Content-Encoding", "gzip, gzip, gzip");
        res.set_content("anything", "application/json");
      });
    iora::core::ThreadPool pool(2, 4, 2s);
    JsonRpcClient client(pool, fastConfig());
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }

  SECTION("a malformed gzip response body throws")
  {
    ProgrammableServer server;
    server.setResponder(
      [](const ProgrammableServer::Request &, ProgrammableServer::Response &res)
      {
        res.set_header("Content-Encoding", "gzip");
        res.set_content("this is not a gzip stream", "application/json");
      });
    iora::core::ThreadPool pool(2, 4, 2s);
    JsonRpcClient client(pool, fastConfig());
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }

  SECTION("a truncated gzip response body throws")
  {
    ProgrammableServer server;
    std::string full = iora::util::Gzip::compress(R"({"jsonrpc":"2.0","result":"x","id":0})");
    const std::string truncated = full.substr(0, full.size() - 4); // cut the trailer
    server.setResponder(
      [truncated](const ProgrammableServer::Request &, ProgrammableServer::Response &res)
      {
        res.set_header("Content-Encoding", "gzip");
        res.set_content(truncated, "application/json");
      });
    iora::core::ThreadPool pool(2, 4, 2s);
    JsonRpcClient client(pool, fastConfig());
    REQUIRE_THROWS_AS(client.call(server.url(), "m", Json(nullptr), kNoHeaders), JsonRpcError);
  }
}

// Slice-B review M1 (task-7.1 required verification + B-cpp L-3): ~HttpClient must
// be virtual so a Config::httpClientFactory returning a subclass is destroyed
// correctly through the pool's unique_ptr<HttpClient> (F-3 UB otherwise). The
// static_assert is the compiled regression guard task-7.1 requires; the runtime
// case is the L-3 end-to-end proof that the derived destructor actually fires.
static_assert(std::has_virtual_destructor<iora::network::HttpClient>::value,
              "HttpClient must have a virtual destructor (Config::httpClientFactory returns a "
              "subclass owned by the pool as unique_ptr<HttpClient>; a non-virtual dtor is UB)");

TEST_CASE("jsonrpc client: a factory subclass's destructor runs (virtual ~HttpClient, M1/L-3)",
          "[jsonrpc_client][lifetime]")
{
  struct FlagHttpClient : iora::network::HttpClient
  {
    std::atomic<int> *counter;
    FlagHttpClient(const iora::network::HttpClient::Config &cfg, std::atomic<int> *c)
        : iora::network::HttpClient(cfg), counter(c)
    {
    }
    ~FlagHttpClient() override { counter->fetch_add(1, std::memory_order_relaxed); }
  };

  std::atomic<int> derivedDtorCount{0};
  ProgrammableServer server;
  server.setResponder(ProgrammableServer::successResult(Json("ok")));
  iora::core::ThreadPool pool(2, 4, 2s);
  {
    Config cfg = fastConfig();
    cfg.httpClientFactory =
      [&derivedDtorCount](const std::string &, const iora::network::HttpClient::Config &derived)
        -> std::unique_ptr<iora::network::HttpClient>
    {
      return std::make_unique<FlagHttpClient>(derived, &derivedDtorCount); // R-MEM-1: no raw new
    };
    JsonRpcClient client(pool, cfg);
    REQUIRE(client.call(server.url(), "m", Json(nullptr), kNoHeaders).is_string());
    REQUIRE(derivedDtorCount.load() == 0); // wrapper still pooled and alive
  }
  // The client (and its pool) are destroyed here: the pooled FlagHttpClient is
  // deleted through a base unique_ptr<HttpClient>. A non-virtual ~HttpClient would
  // skip ~FlagHttpClient and leave the counter at 0 (and leak/UB).
  REQUIRE(derivedDtorCount.load() >= 1);
}

// ── task-6.4: connection-refused via a bound-but-not-listening endpoint ──────
TEST_CASE("jsonrpc client: connection refused fails promptly (task-6.4)",
          "[jsonrpc_client][refused]")
{
  testnet::RefusingEndpoint refusing; // NOT an unbound port (WSL2 blackholes the SYN)
  iora::core::ThreadPool pool(2, 4, 2s);
  Config cfg = fastConfig();
  cfg.maxRetries = 0; // no retries -> a single prompt failure
  JsonRpcClient client(pool, cfg);

  const std::string url = "http://127.0.0.1:" + std::to_string(refusing.port()) + "/rpc";
  const auto t0 = std::chrono::steady_clock::now();
  REQUIRE_THROWS_AS(client.call(url, "m", Json(nullptr), kNoHeaders), std::exception);
  const auto elapsed =
    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - t0).count();
  REQUIRE(elapsed < 5); // well under the 10s default connectionTimeout
}
