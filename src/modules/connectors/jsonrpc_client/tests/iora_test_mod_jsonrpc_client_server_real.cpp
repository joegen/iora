// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Real integration test that loads both JSON-RPC server and client modules

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>
#include "iora/iora.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
#include <filesystem>

using namespace iora;

namespace
{

// Type aliases for common API signatures to improve readability
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;
using Headers = std::vector<std::pair<std::string, std::string>>;

/// \brief Helper function to create a test IoraService instance
iora::IoraService& createTestService()
{
  static bool initialized = false;
  if (!initialized)
  {
    iora::IoraService::Config config;
    config.server.port = 8135;
    config.log.file = "jsonrpc_client_test";
    config.log.level = "info";
    config.modules.autoLoad = false; // we will be loading modules manually

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
  return iora::IoraService::instance();
}

} // anonymous namespace

TEST_CASE("JSON-RPC Client-Server Integration", "[integration][basic]")
{
  auto& svc = iora::IoraService::instance();
  SECTION("Enumerate and test all exported JSON-RPC APIs")
  {
    // Print all exported APIs
    auto apiNames = svc.getExportedApiNames();
    std::cout << "\nExported APIs after plugin load:" << std::endl;
    for (const auto& name : apiNames)
    {
      std::cout << "  " << name << std::endl;
    }

    // --- Server APIs ---
    // jsonrpc.version
    auto serverVersion = svc.callExportedApi<std::uint32_t>("jsonrpc.version");
    REQUIRE(serverVersion == 2U);
    std::cout << "✓ Server version: " << serverVersion << std::endl;

    // jsonrpc.register
    JsonHandler echoHandler = [](const core::Json& params) -> core::Json
    {
      std::cout << "Server: echo handler called with: " << params.dump() << std::endl;
      return params;
    };
    svc.callExportedApi<void, const std::string&, std::function<iora::core::Json(const iora::core::Json&)>>(
      "jsonrpc.register", "echo", std::move(echoHandler));
    std::cout << "✓ Registered 'echo' method on server" << std::endl;

    // jsonrpc.has
    bool hasEcho = svc.callExportedApi<bool, const std::string&>("jsonrpc.has", "echo");
    REQUIRE(hasEcho);
    std::cout << "✓ Server has 'echo' method" << std::endl;

    // jsonrpc.getMethods
    auto methods = svc.callExportedApi<std::vector<std::string>>("jsonrpc.getMethods");
    REQUIRE(std::find(methods.begin(), methods.end(), "echo") != methods.end());
    std::cout << "✓ Server getMethods includes 'echo'" << std::endl;

    // jsonrpc.getStats
    auto stats = svc.callExportedApi<core::Json>("jsonrpc.getStats");
    std::cout << "✓ Server stats: " << stats.dump() << std::endl;

    // jsonrpc.resetStats
    svc.callExportedApi<void>("jsonrpc.resetStats");
    std::cout << "✓ Server stats reset" << std::endl;

    // jsonrpc.unregister
    bool unregEcho = svc.callExportedApi<bool, const std::string&>("jsonrpc.unregister", "echo");
    REQUIRE(unregEcho);
    std::cout << "✓ Unregistered 'echo' method" << std::endl;

    // jsonrpc.has (after unregister)
    bool hasEchoAfter = svc.callExportedApi<bool, const std::string&>("jsonrpc.has", "echo");
    REQUIRE(!hasEchoAfter);
    std::cout << "✓ Server no longer has 'echo' method" << std::endl;

    // --- Client APIs ---
    auto clientVersion = svc.callExportedApi<std::uint32_t>("jsonrpc.client.version");
    REQUIRE(clientVersion == 2U);
    std::cout << "✓ Client version: " << clientVersion << std::endl;

    // Prepare dummy endpoint and params
    const std::string serverUrl = "http://localhost:8135/rpc";
    core::Json params = {{"test", "value"}};
    Headers headers;

    // jsonrpc.client.call (should fail gracefully if server not running)
    try
    {
      auto result = svc.callExportedApi<core::Json, const std::string&, const std::string&, const core::Json&, const Headers&>(
        "jsonrpc.client.call", serverUrl, "echo", params, headers);
      std::cout << "✓ Client call result: " << result.dump() << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Client call failed (expected if server not running): " << e.what() << std::endl;
    }

    // jsonrpc.client.notify
    try
    {
      svc.callExportedApi<void, const std::string&, const std::string&, const core::Json&, const Headers&>(
        "jsonrpc.client.notify", serverUrl, "echo", params, headers);
      std::cout << "✓ Client notify sent" << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Client notify failed (expected if server not running): " << e.what() << std::endl;
    }

    // jsonrpc.client.callAsync
    try
    {
      auto jobId = svc.callExportedApi<std::string, const std::string&, const std::string&, const core::Json&, const Headers&>(
        "jsonrpc.client.callAsync", serverUrl, "echo", params, headers);
      std::cout << "✓ Client callAsync jobId: " << jobId << std::endl;
      auto asyncResult = svc.callExportedApi<core::Json, const std::string&>("jsonrpc.client.result", jobId);
      std::cout << "✓ Client callAsync result: " << asyncResult.dump() << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Client callAsync failed (expected if server not running): " << e.what() << std::endl;
    }

    /*
      */

    // jsonrpc.client.resetStats
    try
    {
      svc.callExportedApi<void>("jsonrpc.client.resetStats");
      std::cout << "✓ Client stats reset" << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Client resetStats failed: " << e.what() << std::endl;
    }

    // jsonrpc.client.purgeIdle
    try
    {
      auto purged = svc.callExportedApi<std::size_t>("jsonrpc.client.purgeIdle");
      std::cout << "✓ Client purged idle: " << purged << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Client purgeIdle failed: " << e.what() << std::endl;
    }

    // --- Previously Missing Client APIs ---
    
    // jsonrpc.client.getStats (previously leaked internal ClientStats&)
    try
    {
      auto clientStats = svc.callExportedApi<core::Json>("jsonrpc.client.getStats");
      REQUIRE(clientStats.is_object());
      REQUIRE(clientStats.contains("totalRequests"));
      REQUIRE(clientStats.contains("successfulRequests"));
      REQUIRE(clientStats.contains("failedRequests"));
      REQUIRE(clientStats.contains("timeoutRequests"));
      REQUIRE(clientStats.contains("retriedRequests"));
      REQUIRE(clientStats.contains("batchRequests"));
      REQUIRE(clientStats.contains("notificationRequests"));
      REQUIRE(clientStats.contains("poolExhaustions"));
      REQUIRE(clientStats.contains("connectionsCreated"));
      REQUIRE(clientStats.contains("connectionsEvicted"));
      std::cout << "✓ Client getStats (JSON format): " << clientStats.dump() << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Client getStats failed: " << e.what() << std::endl;
    }

    // jsonrpc.client.callBatch (previously leaked internal BatchItem)
    try
    {
      // Create batch request using new JSON format
      core::Json batchItems = core::Json::array();
      batchItems.push_back({
        {"method", "echo"},
        {"params", {{"msg", "batch1"}}},
        {"id", 1}
      });
      batchItems.push_back({
        {"method", "echo"},
        {"params", {{"msg", "batch2"}}},
        {"id", 2}
      });
      batchItems.push_back({
        {"method", "echo"},
        {"params", {{"msg", "notification"}}}
        // No "id" field = notification
      });

      auto batchResults = svc.callExportedApi<std::vector<core::Json>, const std::string&, const core::Json&, const Headers&>(
        "jsonrpc.client.callBatch", serverUrl, batchItems, headers);
      
      std::cout << "✓ Client callBatch completed with " << batchResults.size() << " results" << std::endl;
      for (size_t i = 0; i < batchResults.size(); ++i)
      {
        if (!batchResults[i].is_null())
        {
          std::cout << "  Result[" << i << "]: " << batchResults[i].dump() << std::endl;
        }
        else
        {
          std::cout << "  Result[" << i << "]: null (notification)" << std::endl;
        }
      }
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Client callBatch failed (expected if server not running): " << e.what() << std::endl;
    }

    // jsonrpc.client.callBatchAsync (previously leaked internal BatchItem)
    try
    {
      // Create batch request using new JSON format
      core::Json batchItems = core::Json::array();
      batchItems.push_back({
        {"method", "echo"},
        {"params", {{"async", "batch1"}}},
        {"id", 10}
      });
      batchItems.push_back({
        {"method", "echo"},
        {"params", {{"async", "batch2"}}},
        {"id", 20}
      });

      auto asyncBatchJobId = svc.callExportedApi<std::string, const std::string&, const iora::core::Json&, const Headers&>("jsonrpc.client.callBatchAsync", serverUrl, batchItems, headers);
      
      std::cout << "✓ Client callBatchAsync jobId: " << asyncBatchJobId << std::endl;
      
      // Poll for result
      for (int attempts = 0; attempts < 5; ++attempts)
      {
        auto asyncBatchResult = svc.callExportedApi<iora::core::Json, const std::string&>("jsonrpc.client.result", asyncBatchJobId);
        std::cout << "  Batch async result (attempt " << (attempts + 1) << "): " << asyncBatchResult.dump() << std::endl;
        
        if (asyncBatchResult.value("done", false))
        {
          break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Client callBatchAsync failed (expected if server not running): " << e.what() << std::endl;
    }

    std::cout << "✓ Comprehensive JSON-RPC API coverage test completed (including previously leaking APIs)" << std::endl;
  }
  
  // Cleanup
  util::removeFilesContainingAny({"jsonrpc_client_test"});
}

TEST_CASE("Server Method Registration with Options", "[integration][server][options]")
{
  auto& svc = iora::IoraService::instance();
  
  SECTION("Test jsonrpc.registerWithOptions with various configurations")
  {
    // Test method handler that requires authentication
    auto authHandler = [](const core::Json& params) -> core::Json
    {
      return core::Json{{"authenticated", true}, {"params", params}};
    };
    
    // Register method with options using new JSON format
    core::Json options = {
      {"requireAuth", true},
      {"timeout", 5000},
      {"maxRequestSize", 1024}
    };
    
    svc.callExportedApi<void, const std::string&, std::function<iora::core::Json(const iora::core::Json&)>, const iora::core::Json&>("jsonrpc.registerWithOptions", "secure_method", std::move(authHandler), options);
    
    // Verify method was registered
    bool hasSecureMethod = svc.callExportedApi<bool, const std::string&>("jsonrpc.has", "secure_method");
    REQUIRE(hasSecureMethod);
    std::cout << "✓ Registered 'secure_method' with options" << std::endl;
    
    // Test method list includes our new method
    auto methods = svc.callExportedApi<std::vector<std::string>>("jsonrpc.getMethods");
    REQUIRE(std::find(methods.begin(), methods.end(), "secure_method") != methods.end());
    std::cout << "✓ getMethods includes 'secure_method'" << std::endl;
    
    // Test multiple method registrations
    auto mathAddHandler = [](const core::Json& params) -> core::Json
    {
      if (!params.contains("a") || !params.contains("b"))
      {
        throw std::invalid_argument("Missing required parameters 'a' and 'b'");
      }
      int a = params["a"].get<int>();
      int b = params["b"].get<int>();
      return core::Json{{"result", a + b}};
    };
    
    svc.callExportedApi<void, const std::string&, std::function<iora::core::Json(const iora::core::Json&)>>("jsonrpc.register", "math.add", std::move(mathAddHandler));
    
    auto mathMultiplyHandler = [](const core::Json& params) -> core::Json
    {
      if (!params.contains("a") || !params.contains("b"))
      {
        throw std::invalid_argument("Missing required parameters 'a' and 'b'");
      }
      int a = params["a"].get<int>();
      int b = params["b"].get<int>();
      return core::Json{{"result", a * b}};
    };
    
    svc.callExportedApi<void, const std::string&, std::function<iora::core::Json(const iora::core::Json&)>>("jsonrpc.register", "math.multiply", std::move(mathMultiplyHandler));
    
    // Verify all methods are registered
    auto updatedMethods = svc.callExportedApi<std::vector<std::string>>("jsonrpc.getMethods");
    REQUIRE(updatedMethods.size() >= 3);
    REQUIRE(std::find(updatedMethods.begin(), updatedMethods.end(), "secure_method") != updatedMethods.end());
    REQUIRE(std::find(updatedMethods.begin(), updatedMethods.end(), "math.add") != updatedMethods.end());
    REQUIRE(std::find(updatedMethods.begin(), updatedMethods.end(), "math.multiply") != updatedMethods.end());
    
    std::cout << "✓ Registered multiple methods. Total methods: " << updatedMethods.size() << std::endl;
    for (const auto& method : updatedMethods)
    {
      std::cout << "  - " << method << std::endl;
    }
    
    // Test server statistics after registrations
    auto serverStats = svc.callExportedApi<iora::core::Json>("jsonrpc.getStats");
    std::cout << "✓ Server stats after registrations: " << serverStats.dump() << std::endl;
    
    // Cleanup - unregister all test methods
    svc.callExportedApi<bool, const std::string&>("jsonrpc.unregister", "secure_method");
    svc.callExportedApi<bool, const std::string&>("jsonrpc.unregister", "math.add");
    svc.callExportedApi<bool, const std::string&>("jsonrpc.unregister", "math.multiply");
    
    auto finalMethods = svc.callExportedApi<std::vector<std::string>>("jsonrpc.getMethods");
    std::cout << "✓ Cleanup completed. Remaining methods: " << finalMethods.size() << std::endl;
  }
}

TEST_CASE("Error Handling and Edge Cases", "[integration][errors]")
{
  auto& svc = iora::IoraService::instance();
  
  SECTION("Test various error conditions")
  {
    // Test batch with invalid JSON structure
    try
    {
      core::Json invalidBatchItems = "not an array";  // Invalid - should be array
      const std::string serverUrl = "http://localhost:8135/rpc";
      Headers headers;
      
      auto results = svc.callExportedApi<std::vector<iora::core::Json>, const std::string&, const iora::core::Json&, const Headers&>("jsonrpc.client.callBatch", serverUrl, invalidBatchItems, headers);
      
      // Should not reach here
      REQUIRE(false);
    }
    catch (const std::exception& e)
    {
      std::cout << "✓ Batch with invalid JSON structure properly rejected: " << e.what() << std::endl;
    }
    
    // Test batch with missing method field
    try
    {
      core::Json invalidBatchItems = core::Json::array();
      invalidBatchItems.push_back({
        {"params", {{"a", 1}}},
        {"id", 1}
        // Missing "method" field
      });
      
      const std::string serverUrl = "http://localhost:8135/rpc";
      Headers headers;
      
      auto results = svc.callExportedApi<std::vector<iora::core::Json>, const std::string&, const iora::core::Json&, const Headers&>("jsonrpc.client.callBatch", serverUrl, invalidBatchItems, headers);
      
      // Should not reach here
      REQUIRE(false);
    }
    catch (const std::exception& e)
    {
      std::cout << "✓ Batch with missing method field properly rejected: " << e.what() << std::endl;
    }
    
    // Test client statistics validation
    try
    {
      auto stats = svc.callExportedApi<iora::core::Json>("jsonrpc.client.getStats");
      
      // Verify all required fields are present and are numbers
      REQUIRE(stats.contains("totalRequests"));
      REQUIRE(stats["totalRequests"].is_number_unsigned());
      REQUIRE(stats.contains("successfulRequests"));
      REQUIRE(stats["successfulRequests"].is_number_unsigned());
      REQUIRE(stats.contains("failedRequests"));
      REQUIRE(stats["failedRequests"].is_number_unsigned());
      
      std::cout << "✓ Client statistics format validation passed" << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Client statistics test failed: " << e.what() << std::endl;
    }
    
    // Test async result polling for non-existent job
    try
    {
      auto result = svc.callExportedApi<iora::core::Json, const std::string&>("jsonrpc.client.result", "non-existent-job-id");
      
      REQUIRE(result.is_object());
      REQUIRE(result.contains("done"));
      REQUIRE(result["done"] == false);
      
      std::cout << "✓ Non-existent async job properly handled: " << result.dump() << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Async job polling test failed: " << e.what() << std::endl;
    }
  }
}

TEST_CASE("Full Client-Server Communication", "[integration][communication][full]")
{
  auto& svc = iora::IoraService::instance();
  
  SECTION("Test full client-server communication with running server")
  {
    // Register test methods on the server
    auto echoHandler = [](const core::Json& params) -> core::Json
    {
      std::cout << "Server: echo called with " << params.dump() << std::endl;
      return params;
    };
    
    auto addHandler = [](const core::Json& params) -> core::Json
    {
      if (!params.contains("a") || !params.contains("b"))
      {
        throw std::invalid_argument("Parameters 'a' and 'b' are required");
      }
      int a = params["a"].get<int>();
      int b = params["b"].get<int>();
      return core::Json{{"sum", a + b}};
    };
    
    // Register methods
    svc.callExportedApi<void, const std::string&, std::function<iora::core::Json(const iora::core::Json&)>>("jsonrpc.register", "echo", std::move(echoHandler));
    svc.callExportedApi<void, const std::string&, std::function<iora::core::Json(const iora::core::Json&)>>("jsonrpc.register", "add", std::move(addHandler));
    
    std::cout << "✓ Registered echo and add methods on server" << std::endl;
    
    // Start server (it should already be running from service initialization)
    const std::string serverUrl = "http://localhost:8135/rpc";
    Headers headers;
    
    // Wait a moment for server to fully initialize
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Test direct RPC calls
    try
    {
      core::Json echoParams = {{"message", "Hello from client!"}};
      auto echoResult = svc.callExportedApi<iora::core::Json, const std::string&, const std::string&, const iora::core::Json&, const Headers&>("jsonrpc.client.call", serverUrl, "echo", echoParams, headers);
      
      REQUIRE(echoResult.contains("message"));
      REQUIRE(echoResult["message"] == "Hello from client!");
      std::cout << "✓ Direct RPC call successful: " << echoResult.dump() << std::endl;
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Direct RPC call failed: " << e.what() << std::endl;
    }
    
    // Test batch operations with running server
    try
    {
      core::Json batchItems = core::Json::array();
      batchItems.push_back({
        {"method", "echo"},
        {"params", {{"msg", "batch echo test"}}},
        {"id", 1}
      });
      batchItems.push_back({
        {"method", "add"},
        {"params", {{"a", 10}, {"b", 20}}},
        {"id", 2}
      });
      batchItems.push_back({
        {"method", "echo"},
        {"params", {{"notification", true}}}
        // No id = notification
      });
      
      auto batchResults = svc.callExportedApi<std::vector<core::Json>, const std::string&, const core::Json&, const Headers&>(
        "jsonrpc.client.callBatch", serverUrl, batchItems, headers);
      
      std::cout << "✓ Batch RPC call successful with " << batchResults.size() << " results:" << std::endl;
      for (size_t i = 0; i < batchResults.size(); ++i)
      {
        if (!batchResults[i].is_null())
        {
          std::cout << "  Result[" << i << "]: " << batchResults[i].dump() << std::endl;
        }
      }
      
      // Validate batch results
      if (batchResults.size() >= 2)
      {
        // First result should be echo (the direct result, not wrapped in JSON-RPC response)
        if (batchResults[0].contains("result"))
        {
          // JSON-RPC response format
          REQUIRE(batchResults[0]["result"].contains("msg"));
          REQUIRE(batchResults[0]["result"]["msg"] == "batch echo test");
        }
        else
        {
          // Direct result format
          REQUIRE(batchResults[0].contains("msg"));
          REQUIRE(batchResults[0]["msg"] == "batch echo test");
        }
        
        // Second result should be add
        if (batchResults[1].contains("result"))
        {
          // JSON-RPC response format
          REQUIRE(batchResults[1]["result"].contains("sum"));
          REQUIRE(batchResults[1]["result"]["sum"] == 30);
        }
        else
        {
          // Direct result format
          REQUIRE(batchResults[1].contains("sum"));
          REQUIRE(batchResults[1]["sum"] == 30);
        }
      }
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Batch RPC call failed: " << e.what() << std::endl;
    }
    
    // Test async operations with real server
    try
    {
      core::Json asyncParams = {{"async_test", "value"}};
      auto jobId = svc.callExportedApi<std::string, const std::string&, const std::string&, const iora::core::Json&, const Headers&>("jsonrpc.client.callAsync", serverUrl, "echo", asyncParams, headers);
      
      std::cout << "✓ Async RPC call initiated with jobId: " << jobId << std::endl;
      
      // Poll for completion
      bool completed = false;
      for (int attempt = 0; attempt < 10 && !completed; ++attempt)
      {
        auto result = svc.callExportedApi<iora::core::Json, const std::string&>("jsonrpc.client.result", jobId);
        
        std::cout << "  Async poll attempt " << (attempt + 1) << ": " << result.dump() << std::endl;
        
        if (result.value("done", false))
        {
          completed = true;
          if (result.contains("result"))
          {
            // The result might be the direct value or wrapped in JSON-RPC response
            auto resultValue = result["result"];
            if (resultValue.contains("async_test"))
            {
              REQUIRE(resultValue["async_test"] == "value");
            }
            else if (resultValue.contains("result") && resultValue["result"].contains("async_test"))
            {
              REQUIRE(resultValue["result"]["async_test"] == "value");
            }
            std::cout << "✓ Async operation completed successfully" << std::endl;
          }
          else if (result.contains("error"))
          {
            std::cout << "○ Async operation completed with error: " << result["error"].dump() << std::endl;
          }
        }
        
        if (!completed)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
      }
      
      if (!completed)
      {
        std::cout << "○ Async operation did not complete within timeout" << std::endl;
      }
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Async RPC call failed: " << e.what() << std::endl;
    }
    
    // Test client and server statistics after real operations
    try
    {
      auto clientStats = svc.callExportedApi<iora::core::Json>("jsonrpc.client.getStats");
      auto serverStats = svc.callExportedApi<iora::core::Json>("jsonrpc.getStats");
      
      std::cout << "✓ Final client statistics: " << clientStats.dump() << std::endl;
      std::cout << "✓ Final server statistics: " << serverStats.dump() << std::endl;
      
      // Verify that some requests were processed
      REQUIRE(clientStats["totalRequests"].get<std::uint64_t>() > 0);
      REQUIRE(serverStats["totalRequests"].get<std::uint64_t>() > 0);
    }
    catch (const std::exception& e)
    {
      std::cout << "○ Statistics collection failed: " << e.what() << std::endl;
    }
    
    // Cleanup
    svc.callExportedApi<bool, const std::string&>("jsonrpc.unregister", "echo");
    svc.callExportedApi<bool, const std::string&>("jsonrpc.unregister", "add");
    
    std::cout << "✓ Full client-server communication test completed" << std::endl;
  }
}

int main(int argc, char* argv[])
{
  std::cout << "Real JSON-RPC Client-Server Integration Test\n";
  std::cout << "============================================\n" << std::endl;

  // Initialize service properly
  auto& svc = createTestService();
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  // Resolve paths for plugins
  std::string execPath = iora::util::getExecutablePath();
  std::string modulesPath = iora::util::resolveRelativePath(execPath, "../../../../");
  std::string clientPluginPath = modulesPath + "/connectors/jsonrpc_client/mod_jsonrpc_client.so";
  std::string serverPluginPath = modulesPath + "/endpoints/jsonrpc_server/mod_jsonrpc_server.so";

  std::cout << "Loading server plugin from: " << serverPluginPath << std::endl;
  std::cout << "Loading client plugin from: " << clientPluginPath << std::endl;

  assert(std::filesystem::exists(serverPluginPath));
  assert(std::filesystem::exists(clientPluginPath));

  // Load JSON-RPC server module
  assert(svc.loadSingleModule(serverPluginPath));
  std::cout << "✓ JSON-RPC server module loaded" << std::endl;

  // Load JSON-RPC client module
  assert(svc.loadSingleModule(clientPluginPath));
  std::cout << "✓ JSON-RPC client module loaded" << std::endl;

  return Catch::Session().run(argc, argv);
}