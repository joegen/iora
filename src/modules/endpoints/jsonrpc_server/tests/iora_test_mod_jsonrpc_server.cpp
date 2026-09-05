// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#include "../jsonrpc_server.hpp"
#include "iora/iora.hpp"
#include <atomic>
#include <catch2/catch.hpp>
#include <chrono>
#include <cstdio>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace iora::modules::jsonrpc;

namespace
{

/// \brief Helper function to create a test IoraService instance
iora::IoraService &createTestService()
{
  static bool initialized = false;
  if (!initialized)
  {
    iora::IoraService::Config config;
    config.server.port = 8132;
    config.log.file = "jsonrpc_test";
    config.log.level = "info";

    try
    {
      iora::IoraService::shutdown(); // Ensure clean state
    }
    catch (...)
    {
      // Ignore shutdown errors if already shutdown
    }

    iora::IoraService::init(config);
    initialized = true;
  }
  return iora::IoraService::instanceRef();
}

/// \brief Test method handler that echoes parameters
iora::parsers::Json echoHandler(const iora::parsers::Json &params, RpcContext &ctx)
{
  return params;
}

/// \brief Test method handler that throws invalid_argument
iora::parsers::Json invalidParamsHandler(const iora::parsers::Json &params, RpcContext &ctx)
{
  throw std::invalid_argument("Invalid parameters provided");
}

/// \brief Test method handler that throws runtime_error
iora::parsers::Json internalErrorHandler(const iora::parsers::Json &params, RpcContext &ctx)
{
  throw std::runtime_error("Internal processing error");
}

/// \brief Test method handler that requires authentication
iora::parsers::Json authRequiredHandler(const iora::parsers::Json &params, RpcContext &ctx)
{
  if (!ctx.authSubject().has_value())
  {
    throw std::invalid_argument("Authentication required");
  }
  auto result = iora::parsers::Json::object();
  result["user"] = ctx.authSubject().value();
  return result;
}

/// \brief Test method handler with pre/post hooks
iora::parsers::Json hookedHandler(const iora::parsers::Json &params, RpcContext &ctx)
{
  auto result = iora::parsers::Json::object();
  result["processed"] = true;
  return result;
}

/// \brief Run \p fn on a DETACHED thread and wait up to \p timeout for its result.
/// Returns {completed, result}. Unlike std::async(std::launch::async), whose
/// returned future re-BLOCKS in its destructor on a not-ready task, the future here
/// comes from a std::packaged_task and does NOT block on destruction — so a
/// deadlock-regression yields a clean {false, ""} that a REQUIRE turns into a red
/// test instead of hanging at scope exit (M-thread-1). The leaked detached thread
/// is reaped by the CTest TIMEOUT property. On the correct code path fn completes
/// well within the timeout and the thread joins naturally.
/// \brief Sets an atomic<bool> flag true on scope exit, so a mid-flight "may
/// finish" latch is released even if a contending registry call before it throws
/// (e.g. a REQUIRE fails). Without this, a throw would leave the spinning handler
/// stuck and the std::async future's blocking destructor would hang the run instead
/// of failing cleanly (L-TS-1). The CTest TIMEOUT remains the backstop for the
/// distinct case where the contending call itself deadlocks on the server mutex.
struct SetFlagOnExit
{
  std::atomic<bool> &flag;
  ~SetFlagOnExit() { flag.store(true); }
};

std::pair<bool, std::string> runBounded(std::function<std::string()> fn,
                                        std::chrono::milliseconds timeout)
{
  auto task = std::make_shared<std::packaged_task<std::string()>>(std::move(fn));
  std::future<std::string> fut = task->get_future();
  std::thread([task]() { (*task)(); }).detach();
  if (fut.wait_for(timeout) != std::future_status::ready)
  {
    return {false, std::string{}};
  }
  return {true, fut.get()};
}

} // anonymous namespace

TEST_CASE("JsonRpcServer basic method registration", "[jsonrpc][basic]")
{
  JsonRpcServer server;

  SECTION("Register and check method existence")
  {
    REQUIRE_FALSE(server.hasMethod("test"));
    server.registerMethod("test", echoHandler);
    REQUIRE(server.hasMethod("test"));

    auto methods = server.getMethodNames();
    REQUIRE(methods.size() == 1);
    REQUIRE(methods[static_cast<std::size_t>(0)] == "test");
  }

  SECTION("Unregister method")
  {
    server.registerMethod("test", echoHandler);
    REQUIRE(server.hasMethod("test"));
    REQUIRE(server.unregisterMethod("test"));
    REQUIRE_FALSE(server.hasMethod("test"));
    REQUIRE_FALSE(server.unregisterMethod("nonexistent"));
  }

  SECTION("Empty method name validation")
  {
    REQUIRE_THROWS_AS(server.registerMethod("", echoHandler), std::invalid_argument);
  }
}

TEST_CASE("JsonRpcServer method options", "[jsonrpc][options]")
{
  JsonRpcServer server;

  SECTION("Register method with options")
  {
    MethodOptions opts;
    opts.requireAuth = true;
    opts.timeout = std::chrono::milliseconds(1000);
    opts.maxRequestSize = 512;

    server.registerMethod("auth_method", authRequiredHandler, opts);
    REQUIRE(server.hasMethod("auth_method"));
  }

  SECTION("Method with hooks")
  {
    std::atomic<int> preHookCalls{0};
    std::atomic<int> postHookCalls{0};

    MethodOptions opts;
    opts.preHook = [&preHookCalls](const std::string &method, const iora::parsers::Json &params,
                                   RpcContext &ctx) { preHookCalls++; };
    opts.postHook = [&postHookCalls](const std::string &method, const iora::parsers::Json &params,
                                     const iora::parsers::Json &result, RpcContext &ctx)
    { postHookCalls++; };

    server.registerMethod("hooked", hookedHandler, opts);

    auto &service = createTestService();
    RpcContext ctx(service);

    std::string request = R"({"jsonrpc":"2.0","method":"hooked","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);

    REQUIRE(preHookCalls == 1);
    REQUIRE(postHookCalls == 1);
    REQUIRE_FALSE(response.empty());
  }
}

TEST_CASE("JsonRpcServer request validation", "[jsonrpc][validation]")
{
  JsonRpcServer server;
  server.registerMethod("echo", echoHandler);

  auto &service = createTestService();
  RpcContext ctx(service);

  SECTION("Empty request body")
  {
    // W-M8 / LD-12: an empty octet string is invalid JSON — a Parse error
    // (-32700), not a well-formed non-Request-object (-32600). Authorized
    // assertion change (was InvalidRequest).
    std::string response = server.handleRequest("", ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp["jsonrpc"] == "2.0");
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::ParseError));
  }

  SECTION("Whitespace-only request body (W-M8)")
  {
    // A whitespace-only body is not empty (body.empty() is false) so it reaches
    // the parser, which rejects it as invalid JSON -> -32700, consistent with the
    // empty-body case above.
    std::string response = server.handleRequest("   \t\n  ", ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::ParseError));
  }

  SECTION("Invalid JSON")
  {
    std::string response = server.handleRequest("{invalid json", ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp["jsonrpc"] == "2.0");
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::ParseError));
  }

  SECTION("Missing jsonrpc version")
  {
    std::string request = R"({"method":"echo","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
  }

  SECTION("Wrong jsonrpc version")
  {
    std::string request = R"({"jsonrpc":"1.0","method":"echo","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
  }

  SECTION("Wrong-typed jsonrpc member does not throw and is -32600 (W-H2)")
  {
    // The prior unguarded get<std::string>() threw std::bad_variant_access when
    // jsonrpc was a non-string JSON type — a type derived from std::exception but
    // NOT runtime_error/invalid_argument, so it escaped every catch, became an
    // HTTP 500, and (in a batch) discarded already-computed siblings. Each of
    // these must now be a well-formed -32600 envelope, and handleRequest must not
    // throw. DISPATCHER-LEVEL: assert the JSON code, not an HTTP status.
    const std::vector<std::string> requests = {
      R"({"jsonrpc":2.0,"method":"echo","id":1})",     // number
      R"({"jsonrpc":null,"method":"echo","id":1})",    // null
      R"({"jsonrpc":true,"method":"echo","id":1})",    // bool
      R"({"jsonrpc":{"v":"2.0"},"method":"echo","id":1})", // object
      R"({"jsonrpc":["2.0"],"method":"echo","id":1})"};    // array
    for (const auto &request : requests)
    {
      std::string response;
      REQUIRE_NOTHROW(response = server.handleRequest(request, ctx));
      iora::parsers::Json resp = iora::parsers::Json::parseString(response);
      REQUIRE(resp.contains("error"));
      REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
    }
  }

  SECTION("Missing method")
  {
    std::string request = R"({"jsonrpc":"2.0","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
  }

  SECTION("Empty method name")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
  }

  SECTION("Non-string method")
  {
    std::string request = R"({"jsonrpc":"2.0","method":123,"params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
  }
}

TEST_CASE("JsonRpcServer id-type validation (LD-12, pre-dispatch)", "[jsonrpc][idtype]")
{
  JsonRpcServer server;
  std::atomic<bool> handlerRan{false};
  server.registerMethod("sideeffect",
                        [&handlerRan](const iora::parsers::Json &p, RpcContext &) -> iora::parsers::Json
                        {
                          handlerRan = true;
                          return p;
                        });
  server.registerMethod("echo", echoHandler);

  auto &service = createTestService();
  RpcContext ctx(service);

  // An id of a type outside {String, Number, Null} is an Invalid Request (§4). It
  // is rejected PRE-DISPATCH (handler must NOT run) and, because the id cannot be
  // echoed, the envelope carries id:null (§5) — never the offending value.
  auto expectRejectedIdNull = [&](const std::string &request)
  {
    handlerRan = false;
    std::string response;
    REQUIRE_NOTHROW(response = server.handleRequest(request, ctx));
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
    REQUIRE(resp["id"].is_null());
    REQUIRE_FALSE(handlerRan); // proves the check ran BEFORE dispatch
  };

  SECTION("object id -> -32600 id:null, handler NOT run")
  {
    expectRejectedIdNull(R"({"jsonrpc":"2.0","method":"sideeffect","params":{},"id":{"a":1}})");
  }
  SECTION("array id -> -32600 id:null, handler NOT run")
  {
    expectRejectedIdNull(R"({"jsonrpc":"2.0","method":"sideeffect","params":{},"id":[1,2]})");
  }
  SECTION("boolean id -> -32600 id:null (positive allowlist catches bool)")
  {
    expectRejectedIdNull(R"({"jsonrpc":"2.0","method":"sideeffect","params":{},"id":true})");
  }
  SECTION("string / number / null ids are still answered normally")
  {
    for (const std::string &idlit : {std::string("\"s\""), std::string("42"), std::string("null")})
    {
      std::string request =
        R"({"jsonrpc":"2.0","method":"echo","params":{},"id":)" + idlit + "}";
      std::string response = server.handleRequest(request, ctx);
      iora::parsers::Json resp = iora::parsers::Json::parseString(response);
      REQUIRE(resp.contains("result"));
    }
  }

  // H-1: a non-representable id combined with ANOTHER structural error (bad jsonrpc,
  // missing/empty/non-string method) must STILL be answered id:null — the echo-site
  // coercion in makeError guarantees this even though those paths run BEFORE the
  // pre-dispatch id-type check. Single request and batch item.
  SECTION("non-representable id on an otherwise-invalid request -> -32600 id:null (H-1)")
  {
    const std::vector<std::string> requests = {
      R"({"jsonrpc":"2.0","id":{"a":1}})",                 // missing method
      R"({"method":"echo","id":[1,2]})",                   // missing jsonrpc
      R"({"jsonrpc":"2.0","method":"","id":true})",        // empty method + boolean id
      R"({"jsonrpc":"bad","method":"echo","id":{"a":1}})", // wrong jsonrpc string
      R"({"jsonrpc":123,"method":"echo","id":[1,2]})",     // wrong-typed jsonrpc
      R"({"jsonrpc":"2.0","method":1,"id":{"a":1}})"};     // non-string method
    for (const auto &request : requests)
    {
      std::string response;
      REQUIRE_NOTHROW(response = server.handleRequest(request, ctx));
      iora::parsers::Json resp = iora::parsers::Json::parseString(response);
      REQUIRE(resp.contains("error"));
      REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
      REQUIRE(resp["id"].is_null()); // never echo the non-representable id
    }
  }

  SECTION("Policy A: a valid SCALAR id IS echoed on an Invalid Request")
  {
    // {"jsonrpc":"1.0",...,"id":42} is an Invalid Request (wrong version) but 42 is a
    // representable id, so it is echoed (human decision 2026-09-05, Policy A).
    std::string response =
      server.handleRequest(R"({"jsonrpc":"1.0","method":"echo","params":{},"id":42})", ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
    REQUIRE(resp["id"] == 42);
  }

  SECTION("H-1 in a batch: a non-representable-id item errors id:null, siblings unaffected")
  {
    std::string req = R"([)"
                      R"({"jsonrpc":"2.0","method":"echo","params":{"v":1},"id":1},)"
                      R"({"jsonrpc":"2.0","id":{"a":1}},)" // bad id + missing method
                      R"({"jsonrpc":"2.0","method":"echo","params":{"v":3},"id":3})"
                      R"(])";
    std::string response = server.handleRequest(req, ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.size() == 3);
    REQUIRE(resp[static_cast<std::size_t>(0)].contains("result"));
    REQUIRE(resp[1]["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
    REQUIRE(resp[1]["id"].is_null());
    REQUIRE(resp[2].contains("result"));
  }
}

TEST_CASE("JsonRpcServer notification suppression (W-H1, §4.1/§5 boundary)", "[jsonrpc][notify]")
{
  JsonRpcServer server;
  server.registerMethod("echo", echoHandler);
  server.registerMethod("boom", internalErrorHandler); // throws std::runtime_error
  MethodOptions authOpts;
  authOpts.requireAuth = true;
  server.registerMethod("secure", echoHandler, authOpts);
  MethodOptions smallOpts;
  smallOpts.maxRequestSize = 1;
  server.registerMethod("tiny", echoHandler, smallOpts);

  auto &service = createTestService();
  RpcContext ctx(service);

  // ── SUPPRESS side: the four post-lookup paths, for a NOTIFICATION (no id). §4.1:
  //    "The Server MUST NOT reply to a Notification, including those within a batch."
  SECTION("notification to an unknown method -> empty (MethodNotFound suppressed)")
  {
    REQUIRE(server.handleRequest(R"({"jsonrpc":"2.0","method":"doesNotExist"})", ctx).empty());
  }
  SECTION("notification whose handler throws -> empty")
  {
    REQUIRE(server.handleRequest(R"({"jsonrpc":"2.0","method":"boom"})", ctx).empty());
  }
  SECTION("notification failing auth -> empty")
  {
    REQUIRE(server.handleRequest(R"({"jsonrpc":"2.0","method":"secure"})", ctx).empty());
  }
  SECTION("notification exceeding maxRequestSize -> empty")
  {
    REQUIRE(server
              .handleRequest(R"({"jsonrpc":"2.0","method":"tiny","params":{"x":"aaaaaaaaaa"}})", ctx)
              .empty());
  }
  SECTION("batch of two notifications, one to an unknown method -> empty overall")
  {
    std::string req = R"([{"jsonrpc":"2.0","method":"echo","params":{}},)"
                      R"({"jsonrpc":"2.0","method":"doesNotExist"}])";
    REQUIRE(server.handleRequest(req, ctx).empty());
  }
  SECTION("batch of only successful notifications -> empty string, never [] (L-5)")
  {
    std::string req = R"([{"jsonrpc":"2.0","method":"echo","params":{}},)"
                      R"({"jsonrpc":"2.0","method":"echo","params":{}}])";
    REQUIRE(server.handleRequest(req, ctx).empty());
  }
  SECTION("batch of only FAILED notifications increments successfulRequests (documented, LOW-2)")
  {
    server.resetStats();
    std::string req = R"([{"jsonrpc":"2.0","method":"doesNotExist"},)"
                      R"({"jsonrpc":"2.0","method":"alsoMissing"}])";
    REQUIRE(server.handleRequest(req, ctx).empty());
    const auto &stats = server.getStats();
    REQUIRE(stats.batchRequests == 1);
    REQUIRE(stats.successfulRequests == 1); // errorCount==0 after suppression
    REQUIRE(stats.failedRequests == 0);
  }

  // ── KEEP side: EVERY pre-lookup structural failure answers id:null, even with no
  //    id present (§5: an Invalid Request whose id cannot be determined -> id:null).
  auto expectEnvelopeIdNull = [&](const std::string &req)
  {
    std::string response = server.handleRequest(req, ctx);
    REQUIRE_FALSE(response.empty());
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
    REQUIRE(resp["id"].is_null());
  };
  SECTION("no method, no id -> -32600 id:null") { expectEnvelopeIdNull(R"({"jsonrpc":"2.0"})"); }
  SECTION("no jsonrpc, no id -> -32600 id:null") { expectEnvelopeIdNull(R"({"method":"x"})"); }
  SECTION("empty method, no id -> -32600 id:null")
  {
    expectEnvelopeIdNull(R"({"jsonrpc":"2.0","method":""})");
  }
  SECTION("literal §6 non-string-method example, no id -> -32600 id:null (LOW-1)")
  {
    expectEnvelopeIdNull(R"({"jsonrpc":"2.0","method":1,"params":"bar"})");
  }
  SECTION("non-object items in a batch -> id:null envelopes ([1,2,3] -> three -32600)")
  {
    std::string response = server.handleRequest(R"([1,2,3])", ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.is_array());
    REQUIRE(resp.size() == 3);
    for (const auto &e : resp)
    {
      REQUIRE(e.contains("error"));
      REQUIRE(e["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
      REQUIRE(e["id"].is_null());
    }
  }
  SECTION("a request with id:null is a REQUEST, answered (not a notification) (L-2)")
  {
    std::string response =
      server.handleRequest(R"({"jsonrpc":"2.0","method":"echo","params":{"k":"v"},"id":null})", ctx);
    REQUIRE_FALSE(response.empty());
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("result"));
    REQUIRE(resp["id"].is_null());
  }
}

TEST_CASE("JsonRpcServer canonical §6 mixed batch", "[jsonrpc][batch][spec]")
{
  JsonRpcServer server;
  server.registerMethod("echo", echoHandler);
  // Register notify_hello so the batch's notification is a SUCCESSFUL one (its
  // suppression exercises the success-for-notification path, matching §6 literally
  // — not a MethodNotFound-for-notification suppression) (web-LOW-1).
  server.registerMethod("notify_hello", echoHandler);

  auto &service = createTestService();
  RpcContext ctx(service);

  // The interleaving where suppression and id-bearing responses coexist — the exact
  // place an off-by-one appears. Six items: two id-bearing requests (ids 1, 2), one
  // SUCCESSFUL notification (no entry), one {"foo":"boo"} structural failure
  // (id:null), one unknown-method REQUEST with id "5" (-32601, id "5" ECHOED), one
  // request id 9.
  std::string req = R"([)"
                    R"({"jsonrpc":"2.0","method":"echo","params":{"v":1},"id":1},)"
                    R"({"jsonrpc":"2.0","method":"notify_hello","params":[7]},)"
                    R"({"jsonrpc":"2.0","method":"echo","params":{"v":2},"id":2},)"
                    R"({"foo":"boo"},)"
                    R"({"jsonrpc":"2.0","method":"unknownMethod","params":{},"id":"5"},)"
                    R"({"jsonrpc":"2.0","method":"echo","params":{"v":9},"id":9})"
                    R"(])";
  std::string response = server.handleRequest(req, ctx);
  iora::parsers::Json resp = iora::parsers::Json::parseString(response);
  REQUIRE(resp.is_array());
  REQUIRE(resp.size() == 5); // the notification produces NO entry (5, not 6)

  // Order is preserved minus the suppressed notification.
  REQUIRE(resp[static_cast<std::size_t>(0)]["id"] == 1);
  REQUIRE(resp[static_cast<std::size_t>(0)].contains("result"));
  REQUIRE(resp[1]["id"] == 2);
  REQUIRE(resp[1].contains("result"));
  REQUIRE(resp[2]["id"].is_null()); // {"foo":"boo"} -> -32600 id:null
  REQUIRE(resp[2]["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
  REQUIRE(resp[3]["id"] == "5"); // unknown method WITH an id -> id ECHOED
  REQUIRE(resp[3]["error"]["code"] == static_cast<int>(ErrorCode::MethodNotFound));
  REQUIRE(resp[4]["id"] == 9);
  REQUIRE(resp[4].contains("result"));
}

TEST_CASE("JsonRpcServer per-item dispatch is throw-proof (W-H2 batch + structural net)",
          "[jsonrpc][structnet]")
{
  JsonRpcServer server;
  server.registerMethod("echo", echoHandler);
  server.registerMethod("throwInt",
                        [](const iora::parsers::Json &, RpcContext &) -> iora::parsers::Json
                        { throw 42; }); // NOT derived from std::exception

  auto &service = createTestService();
  RpcContext ctx(service);

  SECTION("a wrong-typed jsonrpc sibling returns all entries, not a 500 (W-H2 batch)")
  {
    std::string req = R"([)"
                      R"({"jsonrpc":"2.0","method":"echo","params":{"v":1},"id":1},)"
                      R"({"jsonrpc":2.0,"method":"echo","id":2},)"
                      R"({"jsonrpc":"2.0","method":"echo","params":{"v":3},"id":3})"
                      R"(])";
    std::string response;
    REQUIRE_NOTHROW(response = server.handleRequest(req, ctx));
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.is_array());
    REQUIRE(resp.size() == 3);
    REQUIRE(resp[static_cast<std::size_t>(0)].contains("result"));
    REQUIRE(resp[1].contains("error"));
    REQUIRE(resp[1]["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
    REQUIRE(resp[2].contains("result"));
  }

  SECTION("single request: a non-std::exception handler throw -> InternalError, no escape")
  {
    std::string response;
    REQUIRE_NOTHROW(response =
                      server.handleRequest(R"({"jsonrpc":"2.0","method":"throwInt","id":1})", ctx));
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InternalError));
    REQUIRE(resp["id"] == 1);
  }

  SECTION("batch: a non-std::exception item errors alone; siblings survive")
  {
    std::string req = R"([)"
                      R"({"jsonrpc":"2.0","method":"echo","params":{"v":1},"id":1},)"
                      R"({"jsonrpc":"2.0","method":"throwInt","id":2},)"
                      R"({"jsonrpc":"2.0","method":"echo","params":{"v":3},"id":3})"
                      R"(])";
    std::string response;
    REQUIRE_NOTHROW(response = server.handleRequest(req, ctx));
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.size() == 3);
    REQUIRE(resp[static_cast<std::size_t>(0)].contains("result"));
    REQUIRE(resp[1].contains("error"));
    REQUIRE(resp[2].contains("result"));
  }

  SECTION("notification whose handler throws a non-std::exception -> suppressed")
  {
    REQUIRE(server.handleRequest(R"({"jsonrpc":"2.0","method":"throwInt"})", ctx).empty());
  }
}

TEST_CASE("JsonRpcServer copy-then-invoke: handlers/hooks may re-enter the server",
          "[jsonrpc][reentrancy]")
{
  JsonRpcServer server;
  auto &service = createTestService();

  // The dispatcher copies the handler (and its options/hooks) out under _mutex and
  // releases the lock BEFORE invoking them. If it held _mutex across invocation,
  // any of these re-entrant registry calls would self-deadlock. runBounded turns a
  // deadlock into a clean REQUIRE(ok) FAILURE (its packaged_task future does not
  // re-block on destruction); the CTest TIMEOUT property reaps the leaked thread.
  // Never raise the timeout to make it pass.
  SECTION("handler re-enters registerMethod/unregisterMethod/hasMethod/getMethodNames")
  {
    server.registerMethod("reenter",
                          [&server](const iora::parsers::Json &, RpcContext &) -> iora::parsers::Json
                          {
                            (void)server.hasMethod("reenter");
                            (void)server.getMethodNames();
                            server.registerMethod("dynamic", echoHandler);
                            (void)server.unregisterMethod("dynamic");
                            auto res = iora::parsers::Json::object();
                            res["ok"] = true;
                            return res;
                          });
    auto [ok, response] = runBounded(
      [&]()
      {
        RpcContext ctx(service);
        return server.handleRequest(R"({"jsonrpc":"2.0","method":"reenter","id":1})", ctx);
      },
      std::chrono::seconds(5));
    REQUIRE(ok);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp["result"]["ok"] == true);
  }

  SECTION("preHook and postHook re-enter the registry")
  {
    MethodOptions opts;
    opts.preHook = [&server](const std::string &, const iora::parsers::Json &, RpcContext &)
    {
      (void)server.hasMethod("x");
      (void)server.getMethodNames();
    };
    opts.postHook = [&server](const std::string &, const iora::parsers::Json &,
                              const iora::parsers::Json &, RpcContext &)
    {
      server.registerMethod("post_dyn", echoHandler);
      (void)server.unregisterMethod("post_dyn");
    };
    server.registerMethod("hooked_reenter", echoHandler, opts);
    auto [ok, response] = runBounded(
      [&]()
      {
        RpcContext ctx(service);
        return server.handleRequest(
          R"({"jsonrpc":"2.0","method":"hooked_reenter","params":{},"id":1})", ctx);
      },
      std::chrono::seconds(5));
    REQUIRE(ok);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("result"));
  }

  SECTION("in-flight handler survives a concurrent unregister (handler copy keeps functor alive)")
  {
    std::atomic<bool> inHandler{false};
    std::atomic<bool> mayFinish{false};
    server.registerMethod("slow",
                          [&](const iora::parsers::Json &, RpcContext &) -> iora::parsers::Json
                          {
                            inHandler = true;
                            while (!mayFinish)
                            {
                              std::this_thread::sleep_for(std::chrono::milliseconds(1));
                            }
                            auto res = iora::parsers::Json::object();
                            res["done"] = true;
                            return res;
                          });
    std::future<std::string> fut = std::async(
      std::launch::async,
      [&]()
      {
        RpcContext ctx(service);
        return server.handleRequest(R"({"jsonrpc":"2.0","method":"slow","id":1})", ctx);
      });
    while (!inHandler)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    {
      // Release mayFinish on scope exit even if the REQUIRE throws (L-TS-1), so the
      // spinning handler always completes and the blocking async future can't hang.
      SetFlagOnExit release{mayFinish};
      REQUIRE(server.unregisterMethod("slow")); // remove while the call is mid-flight
    }
    REQUIRE(fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    iora::parsers::Json resp = iora::parsers::Json::parseString(fut.get());
    REQUIRE(resp["result"]["done"] == true);
  }

  SECTION("in-flight handler survives a concurrent register-REPLACE (task-3.2 register-mid-flight)")
  {
    std::atomic<bool> inHandler{false};
    std::atomic<bool> mayFinish{false};
    // Original handler returns version 1; it blocks mid-execution so we can replace
    // it while its copy is in flight. The in-flight (copied) functor must still
    // return its ORIGINAL result (version 1), unaffected by the replacement.
    server.registerMethod("swap",
                          [&](const iora::parsers::Json &, RpcContext &) -> iora::parsers::Json
                          {
                            inHandler = true;
                            while (!mayFinish)
                            {
                              std::this_thread::sleep_for(std::chrono::milliseconds(1));
                            }
                            auto res = iora::parsers::Json::object();
                            res["version"] = 1;
                            return res;
                          });
    std::future<std::string> fut = std::async(
      std::launch::async,
      [&]()
      {
        RpcContext ctx(service);
        return server.handleRequest(R"({"jsonrpc":"2.0","method":"swap","id":1})", ctx);
      });
    while (!inHandler)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    {
      // Release mayFinish on scope exit even if registerMethod throws (L-TS-1).
      SetFlagOnExit release{mayFinish};
      // Replace the method mid-flight with a version-2 handler.
      server.registerMethod("swap",
                            [](const iora::parsers::Json &, RpcContext &) -> iora::parsers::Json
                            {
                              auto res = iora::parsers::Json::object();
                              res["version"] = 2;
                              return res;
                            });
    }
    REQUIRE(fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    iora::parsers::Json resp = iora::parsers::Json::parseString(fut.get());
    REQUIRE(resp["result"]["version"] == 1); // the in-flight copy, not the replacement
    // A fresh call now sees the replacement.
    RpcContext ctx2(service);
    iora::parsers::Json resp2 = iora::parsers::Json::parseString(
      server.handleRequest(R"({"jsonrpc":"2.0","method":"swap","id":2})", ctx2));
    REQUIRE(resp2["result"]["version"] == 2);
  }
}

TEST_CASE("JsonRpcServer single request handling", "[jsonrpc][single]")
{
  JsonRpcServer server;
  server.registerMethod("echo", echoHandler);

  auto &service = createTestService();
  RpcContext ctx(service);

  SECTION("Valid request with result")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"echo","params":{"test":"value"},"id":1})";
    std::string response = server.handleRequest(request, ctx);

    REQUIRE_FALSE(response.empty());
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp["jsonrpc"] == "2.0");
    REQUIRE(resp["id"] == 1);
    REQUIRE(resp.contains("result"));
    REQUIRE(resp["result"]["test"] == "value");
  }

  SECTION("Notification request (no response)")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"echo","params":{"test":"value"}})";
    std::string response = server.handleRequest(request, ctx);
    REQUIRE(response.empty());
  }

  SECTION("Method not found")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"nonexistent","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);

    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::MethodNotFound));
    REQUIRE(resp["id"] == 1);
  }
}

TEST_CASE("JsonRpcServer batch request handling", "[jsonrpc][batch]")
{
  JsonRpcServer server;
  server.registerMethod("echo", echoHandler);
  server.registerMethod("error", invalidParamsHandler);

  auto &service = createTestService();
  RpcContext ctx(service);

  SECTION("Valid batch request")
  {
    std::string request = R"([
      {"jsonrpc":"2.0","method":"echo","params":{"value":1},"id":1},
      {"jsonrpc":"2.0","method":"echo","params":{"value":2},"id":2}
    ])";
    std::string response = server.handleRequest(request, ctx);

    REQUIRE_FALSE(response.empty());
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.is_array());
    REQUIRE(resp.size() == 2);

    REQUIRE(resp[static_cast<std::size_t>(0)]["id"] == 1);
    REQUIRE(resp[static_cast<std::size_t>(0)]["result"]["value"] == 1);
    REQUIRE(resp[1]["id"] == 2);
    REQUIRE(resp[1]["result"]["value"] == 2);
  }

  SECTION("Empty batch request")
  {
    std::string request = R"([])";
    std::string response = server.handleRequest(request, ctx);

    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
  }

  SECTION("Batch too large")
  {
    std::string request = "[";
    for (int i = 0; i < 55; ++i) // Default max is 50
    {
      if (i > 0)
        request += ",";
      request += R"({"jsonrpc":"2.0","method":"echo","params":{},"id":)" + std::to_string(i) + "}";
    }
    request += "]";

    std::string response = server.handleRequest(request, ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
  }

  SECTION("Batch with mixed success and error")
  {
    std::string request = R"([
      {"jsonrpc":"2.0","method":"echo","params":{"value":1},"id":1},
      {"jsonrpc":"2.0","method":"error","params":{},"id":2}
    ])";
    std::string response = server.handleRequest(request, ctx);

    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.is_array());
    REQUIRE(resp.size() == 2);

    REQUIRE(resp[static_cast<std::size_t>(0)]["id"] == 1);
    REQUIRE(resp[static_cast<std::size_t>(0)].contains("result"));
    REQUIRE(resp[1]["id"] == 2);
    REQUIRE(resp[1].contains("error"));
    REQUIRE(resp[1]["error"]["code"] == static_cast<int>(ErrorCode::InvalidParams));
  }

  SECTION("Batch with notifications only")
  {
    std::string request = R"([
      {"jsonrpc":"2.0","method":"echo","params":{"value":1}},
      {"jsonrpc":"2.0","method":"echo","params":{"value":2}}
    ])";
    std::string response = server.handleRequest(request, ctx);
    REQUIRE(response.empty()); // No response for notifications
  }
}

TEST_CASE("JsonRpcServer error handling", "[jsonrpc][errors]")
{
  JsonRpcServer server;
  server.registerMethod("invalid_params", invalidParamsHandler);
  server.registerMethod("internal_error", internalErrorHandler);

  auto &service = createTestService();
  RpcContext ctx(service);

  SECTION("Invalid parameters error")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"invalid_params","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);

    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidParams));
    REQUIRE(resp["id"] == 1);
  }

  SECTION("Internal error")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"internal_error","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);

    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InternalError));
    REQUIRE(resp["id"] == 1);
  }
}

TEST_CASE("JsonRpcServer statistics", "[jsonrpc][stats]")
{
  JsonRpcServer server;
  server.registerMethod("echo", echoHandler);
  server.registerMethod("error", invalidParamsHandler);

  auto &service = createTestService();
  RpcContext ctx(service);

  // Reset stats before testing
  server.resetStats();
  const auto &stats = server.getStats();
  REQUIRE(stats.totalRequests == 0);

  SECTION("Successful request increments stats")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"echo","params":{},"id":1})";
    server.handleRequest(request, ctx);

    REQUIRE(stats.totalRequests == 1);
    REQUIRE(stats.successfulRequests == 1);
    REQUIRE(stats.failedRequests == 0);
  }

  SECTION("Failed request increments stats")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"error","params":{},"id":1})";
    server.handleRequest(request, ctx);

    REQUIRE(stats.totalRequests == 1);
    REQUIRE(stats.successfulRequests == 0);
    REQUIRE(stats.failedRequests == 1);
  }

  SECTION("Notification request increments stats")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"echo","params":{}})";
    server.handleRequest(request, ctx);

    REQUIRE(stats.totalRequests == 1);
    REQUIRE(stats.notificationRequests == 1);
  }

  SECTION("Batch request increments stats")
  {
    std::string request = R"([
      {"jsonrpc":"2.0","method":"echo","params":{},"id":1},
      {"jsonrpc":"2.0","method":"echo","params":{},"id":2}
    ])";
    server.handleRequest(request, ctx);

    REQUIRE(stats.totalRequests == 1);
    REQUIRE(stats.batchRequests == 1);
    REQUIRE(stats.successfulRequests == 1);
  }
}

TEST_CASE("JsonRpcServer context functionality", "[jsonrpc][context]")
{
  JsonRpcServer server;

  // Handler that uses context information
  server.registerMethod(
    "context_test",
    [](const iora::parsers::Json &params, RpcContext &ctx) -> iora::parsers::Json
    {
      iora::parsers::Json result;
      result["hasAuth"] = ctx.authSubject().has_value();
      if (ctx.authSubject().has_value())
      {
        result["authSubject"] = ctx.authSubject().value();
      }
      result["requestSize"] = ctx.metadata().requestSize;
      result["method"] = ctx.metadata().method;
      result["clientId"] = ctx.metadata().clientId;
      return result;
    });

  auto &service = createTestService();

  SECTION("Context without authentication")
  {
    RpcContext ctx(service);
    ctx.metadata().clientId = "test_client";

    std::string request = R"({"jsonrpc":"2.0","method":"context_test","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);

    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("result"));
    REQUIRE(resp["result"]["hasAuth"] == false);
    REQUIRE(resp["result"]["method"] == "context_test");
    REQUIRE(resp["result"]["clientId"] == "test_client");
    REQUIRE(resp["result"]["requestSize"] > 0);
  }

  SECTION("Context with authentication")
  {
    RpcContext ctx(service, "test_user");

    std::string request = R"({"jsonrpc":"2.0","method":"context_test","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);

    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp.contains("result"));
    REQUIRE(resp["result"]["hasAuth"] == true);
    REQUIRE(resp["result"]["authSubject"] == "test_user");
  }
}

TEST_CASE("JsonRpcServer concurrency", "[jsonrpc][concurrency]")
{
  JsonRpcServer server;

  // Thread-safe counter for testing
  std::atomic<int> counter{0};
  server.registerMethod(
    "increment",
    [&counter](const iora::parsers::Json &params, RpcContext &ctx) -> iora::parsers::Json
    {
      int value = ++counter;
      std::this_thread::sleep_for(std::chrono::milliseconds(1)); // Simulate some work
      auto result = iora::parsers::Json::object();
      result["value"] = value;
      return result;
    });

  auto &service = createTestService();

  SECTION("Concurrent requests")
  {
    const int numThreads = 4;
    const int requestsPerThread = 10;
    std::vector<std::thread> threads;
    // vector<char>, not vector<bool>: the latter is bit-packed, so concurrent
    // element writes from 4 threads (below) are a data race even on distinct
    // indices. char elements are independently addressable (L-B).
    std::vector<char> results(numThreads * requestsPerThread, 0);

    for (int t = 0; t < numThreads; ++t)
    {
      threads.emplace_back(
        [&, t]()
        {
          for (int r = 0; r < requestsPerThread; ++r)
          {
            RpcContext ctx(service);
            std::string request = R"({"jsonrpc":"2.0","method":"increment","params":{},"id":)" +
                                  std::to_string(t * requestsPerThread + r) + "}";
            std::string response = server.handleRequest(request, ctx);

            if (!response.empty())
            {
              try
              {
                iora::parsers::Json resp = iora::parsers::Json::parseString(response);
                if (resp.contains("result") && resp["result"].contains("value"))
                {
                  results[t * requestsPerThread + r] = 1;
                }
              }
              catch (...)
              {
                // Parse error, leave as false
              }
            }
          }
        });
    }

    for (auto &thread : threads)
    {
      thread.join();
    }

    // All requests should have succeeded
    for (char result : results)
    {
      REQUIRE(result);
    }

    // Counter should equal total number of requests
    REQUIRE(counter == numThreads * requestsPerThread);
  }
}

TEST_CASE("JsonRpcServer method replacement", "[jsonrpc][replacement]")
{
  JsonRpcServer server;

  // Original handler
  server.registerMethod(
    "test",
    [](const iora::parsers::Json &params, RpcContext &ctx) -> iora::parsers::Json
    {
      auto result = iora::parsers::Json::object();
      result["version"] = 1;
      return result;
    });

  auto &service = createTestService();
  RpcContext ctx(service);

  SECTION("Replace method handler")
  {
    // Test original handler
    std::string request = R"({"jsonrpc":"2.0","method":"test","params":{},"id":1})";
    std::string response = server.handleRequest(request, ctx);

    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp["result"]["version"] == 1);

    // Replace with new handler
    server.registerMethod(
      "test",
      [](const iora::parsers::Json &params, RpcContext &ctx) -> iora::parsers::Json
      {
        auto result = iora::parsers::Json::object();
        result["version"] = 2;
        return result;
      });

    // Test new handler
    response = server.handleRequest(request, ctx);
    resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp["result"]["version"] == 2);
  }
}

TEST_CASE("JsonRpcServer edge cases", "[jsonrpc][edge]")
{
  JsonRpcServer server;
  server.registerMethod("echo", echoHandler);

  auto &service = createTestService();
  RpcContext ctx(service);

  SECTION("Request with null id")
  {
    std::string request = R"({"jsonrpc":"2.0","method":"echo","params":{},"id":null})";
    std::string response = server.handleRequest(request, ctx);

    REQUIRE_FALSE(response.empty());
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp["id"].is_null());
  }

  SECTION("Request with different id types")
  {
    // String id
    std::string request1 = R"({"jsonrpc":"2.0","method":"echo","params":{},"id":"test"})";
    std::string response1 = server.handleRequest(request1, ctx);
    iora::parsers::Json resp1 = iora::parsers::Json::parseString(response1);
    REQUIRE(resp1["id"] == "test");

    // Number id
    std::string request2 = R"({"jsonrpc":"2.0","method":"echo","params":{},"id":42})";
    std::string response2 = server.handleRequest(request2, ctx);
    iora::parsers::Json resp2 = iora::parsers::Json::parseString(response2);
    REQUIRE(resp2["id"] == 42);
  }

  SECTION("Request with different param types")
  {
    // Array params
    std::string request1 = R"({"jsonrpc":"2.0","method":"echo","params":[1,2,3],"id":1})";
    std::string response1 = server.handleRequest(request1, ctx);
    iora::parsers::Json resp1 = iora::parsers::Json::parseString(response1);
    REQUIRE(resp1["result"].is_array());
    REQUIRE(resp1["result"][static_cast<std::size_t>(0)] == 1);

    // Object params
    std::string request2 = R"({"jsonrpc":"2.0","method":"echo","params":{"key":"value"},"id":2})";
    std::string response2 = server.handleRequest(request2, ctx);
    iora::parsers::Json resp2 = iora::parsers::Json::parseString(response2);
    REQUIRE(resp2["result"]["key"] == "value");

    // No params
    std::string request3 = R"({"jsonrpc":"2.0","method":"echo","id":3})";
    std::string response3 = server.handleRequest(request3, ctx);
    iora::parsers::Json resp3 = iora::parsers::Json::parseString(response3);
    REQUIRE(resp3["result"].is_object());
    REQUIRE(resp3["result"].empty());
  }
}

// Plugin integration tests
TEST_CASE("JsonRpcServerPlugin basic functionality", "[jsonrpc][plugin][basic]")
{
  // Create a minimal config for testing
  iora::IoraService::Config config;
  config.server.port = 8133;
  config.state.file = "ioraservice_jsonrpc_state.json";
  config.log.file = "ioraservice_jsonrpc_log";
  config.log.level = "info";

  iora::IoraService::shutdown(); // Ensure clean state
  iora::IoraService::init(config);
  iora::IoraService &svc = iora::IoraService::instanceRef();
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  auto pluginPath = iora::util::resolveRelativePath(iora::util::getExecutableDir(), "../") +
                    "/mod_jsonrpc_server.so";
  REQUIRE(std::filesystem::exists(pluginPath));
  REQUIRE(svc.loadSingleModule(pluginPath));

  SECTION("Plugin API: version")
  {
    auto version = svc.callExportedApi<std::uint32_t>("jsonrpc.version");
    REQUIRE(version == 2U);
  }

  SECTION("Plugin API: register and call methods")
  {
    // Register a test method via plugin API
    auto handler = [](const iora::parsers::Json &params) -> iora::parsers::Json
    {
      auto result = iora::parsers::Json::object();
      result["echo"] = params;
      return result;
    };

    svc.callExportedApi<void, const std::string &,
                        std::function<iora::parsers::Json(const iora::parsers::Json &)>>(
      "jsonrpc.register", "plugin_test", handler);

    // Check if method was registered
    auto hasMethod = svc.callExportedApi<bool, const std::string &>("jsonrpc.has", "plugin_test");
    REQUIRE(hasMethod);

    // Get method list
    auto methods = svc.callExportedApi<std::vector<std::string>>("jsonrpc.getMethods");
    REQUIRE(std::find(methods.begin(), methods.end(), "plugin_test") != methods.end());
  }

  SECTION("Plugin API: unregister methods")
  {
    // Register method
    auto handler = [](const iora::parsers::Json &params) -> iora::parsers::Json { return params; };
    svc.callExportedApi<void, const std::string &,
                        std::function<iora::parsers::Json(const iora::parsers::Json &)>>(
      "jsonrpc.register", "temp_method", handler);
    REQUIRE(svc.callExportedApi<bool, const std::string &>("jsonrpc.has", "temp_method"));

    // Unregister method
    bool removed =
      svc.callExportedApi<bool, const std::string &>("jsonrpc.unregister", "temp_method");
    REQUIRE(removed);
    REQUIRE_FALSE(svc.callExportedApi<bool, const std::string &>("jsonrpc.has", "temp_method"));
  }

  SECTION("Plugin API: method registration with options")
  {
    auto handler = [](const iora::parsers::Json &params) -> iora::parsers::Json
    {
      auto result = iora::parsers::Json::object();
      result["auth_required"] = true;
      return result;
    };

    iora::parsers::Json opts;
    opts["requireAuth"] = true;
    opts["maxRequestSize"] = 1024;

    svc.callExportedApi<void, const std::string &,
                        std::function<iora::parsers::Json(const iora::parsers::Json &)>,
                        const iora::parsers::Json &>("jsonrpc.registerWithOptions", "auth_method",
                                                     handler, opts);

    REQUIRE(svc.callExportedApi<bool, const std::string &>("jsonrpc.has", "auth_method"));
  }

  SECTION("Plugin API: statistics")
  {
    // Reset stats
    svc.callExportedApi<void>("jsonrpc.resetStats");

    // Get initial stats
    auto statsJson = svc.callExportedApi<iora::parsers::Json>("jsonrpc.getStats");
    REQUIRE(statsJson["totalRequests"].get<std::uint64_t>() == 0);

    // Register and simulate some activity (this would normally be done via HTTP requests)
    auto handler = [](const iora::parsers::Json &params) -> iora::parsers::Json { return params; };
    svc.callExportedApi<void, const std::string &,
                        std::function<iora::parsers::Json(const iora::parsers::Json &)>>(
      "jsonrpc.register", "stats_test", handler);

    // Note: HTTP request testing would require starting the webhook server,
    // which is beyond the scope of unit tests. The stats functionality
    // is tested at the JsonRpcServer level above.
  }

  // Cleanup
  iora::util::removeFilesContainingAny(
    {"ioraservice_jsonrpc_log", "ioraservice_jsonrpc_state.json"});
}

TEST_CASE("JsonRpcServerPlugin configuration", "[jsonrpc][plugin][config]")
{
  // Create a minimal config for testing
  iora::IoraService::Config config;
  config.server.port = 8134;
  config.log.level = "info";

  iora::IoraService::shutdown(); // Ensure clean state
  iora::IoraService::init(config);
  iora::IoraService &svc = iora::IoraService::instanceRef();
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  auto pluginPath = iora::util::resolveRelativePath(iora::util::getExecutableDir(), "../") +
                    "/mod_jsonrpc_server.so";

  SECTION("Plugin loads with default configuration")
  {
    REQUIRE(std::filesystem::exists(pluginPath));
    REQUIRE(svc.loadSingleModule(pluginPath));

    // Verify plugin is loaded by checking API availability
    REQUIRE_NOTHROW(svc.callExportedApi<std::uint32_t>("jsonrpc.version"));
  }
}