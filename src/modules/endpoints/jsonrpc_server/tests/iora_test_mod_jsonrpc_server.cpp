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
#include <mutex>
#include <random>
#include <string>
#include <thread>
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
    std::string response = server.handleRequest("", ctx);
    iora::parsers::Json resp = iora::parsers::Json::parseString(response);
    REQUIRE(resp["jsonrpc"] == "2.0");
    REQUIRE(resp.contains("error"));
    REQUIRE(resp["error"]["code"] == static_cast<int>(ErrorCode::InvalidRequest));
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
    std::vector<bool> results(numThreads * requestsPerThread, false);

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
                  results[t * requestsPerThread + r] = true;
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
    for (bool result : results)
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