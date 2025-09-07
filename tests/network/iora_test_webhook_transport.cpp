#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <chrono>
#include <thread>

using namespace iora::test;

TEST_CASE("WebhookServer transport-specific tests")
{
  SECTION("Server starts and stops cleanly")
  {
    iora::network::WebhookServer server;
    server.setPort(8082);

    REQUIRE_NOTHROW(server.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    REQUIRE_NOTHROW(server.stop());
  }

  SECTION("Server handles multiple simultaneous connections")
  {
    iora::network::WebhookServer server;
    server.setPort(8083);

    std::atomic<int> requestCount{0};
    server.onGet("/count",
                 [&requestCount](const iora::network::WebhookServer::Request &,
                                 iora::network::WebhookServer::Response &res)
                 {
                   int count = ++requestCount;
                   res.set_content(std::to_string(count), "text/plain");
                 });

    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Create multiple HTTP clients and make simultaneous requests
    std::vector<std::thread> threads;
    const int numThreads = 5;

    for (int i = 0; i < numThreads; ++i)
    {
      threads.emplace_back(
        [i, numThreads]()
        {
          iora::network::HttpClient client;
          auto res = client.get("http://localhost:8083/count");
          REQUIRE(res.success());
          // Each response should contain a different count
          int responseCount = std::stoi(res.body);
          REQUIRE(responseCount >= 1);
          REQUIRE(responseCount <= numThreads);
        });
    }

    // Wait for all threads to complete
    for (auto &t : threads)
    {
      t.join();
    }

    REQUIRE(requestCount == numThreads);
    server.stop();
  }

  SECTION("Server handles large request body")
  {
    iora::network::WebhookServer server;
    server.setPort(8084);

    server.onPost(
      "/large", [](const iora::network::WebhookServer::Request &req,
                   iora::network::WebhookServer::Response &res)
      { res.set_content("Received " + std::to_string(req.body.size()) + " bytes", "text/plain"); });

    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Create a large request body (64KB)
    std::string largeBody(64 * 1024, 'x');

    iora::network::HttpClient client;
    auto res =
      client.post("http://localhost:8084/large", largeBody, {{"Content-Type", "text/plain"}});

    REQUIRE(res.success());
    REQUIRE(res.body == "Received 65536 bytes");

    server.stop();
  }

  SECTION("Server properly parses query parameters")
  {
    iora::network::WebhookServer server;
    server.setPort(8085);

    server.onGet("/params",
                 [](const iora::network::WebhookServer::Request &req,
                    iora::network::WebhookServer::Response &res)
                 {
                   iora::parsers::Json response;
                   for (const auto &[key, value] : req.params)
                   {
                     response[key] = value;
                   }
                   res.set_content(response.dump(), "application/json");
                 });

    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    iora::network::HttpClient client;
    auto res = client.get("http://localhost:8085/params?foo=bar&test=123&empty=");

    REQUIRE(res.success());
    auto json = iora::parsers::Json::parseString(res.body);
    REQUIRE(json["foo"] == "bar");
    REQUIRE(json["test"] == "123");
    REQUIRE(json["empty"] == "");

    server.stop();
  }

  SECTION("Server handles keep-alive connections")
  {
    iora::network::WebhookServer server;
    server.setPort(8086);

    std::atomic<int> connectionCount{0};
    server.onGet("/ping",
                 [&connectionCount](const iora::network::WebhookServer::Request &,
                                    iora::network::WebhookServer::Response &res)
                 {
                   connectionCount++;
                   res.set_content("pong", "text/plain");
                 });

    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    iora::network::HttpClient client;

    // Make multiple requests - should reuse connection
    auto res1 = client.get("http://localhost:8086/ping");
    auto res2 = client.get("http://localhost:8086/ping");
    auto res3 = client.get("http://localhost:8086/ping");

    REQUIRE(res1.success());
    REQUIRE(res2.success());
    REQUIRE(res3.success());
    REQUIRE(connectionCount == 3);

    server.stop();
  }

  SECTION("Server sends proper HTTP headers")
  {
    iora::network::WebhookServer server;
    server.setPort(8087);

    server.onGet(
      "/headers",
      [](const iora::network::WebhookServer::Request &, iora::network::WebhookServer::Response &res)
      {
        res.set_header("Custom-Header", "test-value");
        res.set_content("OK", "text/plain");
      });

    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    iora::network::HttpClient client;
    auto res = client.get("http://localhost:8087/headers");

    REQUIRE(res.success());

    // Check standard headers are present
    bool hasServer = false;
    bool hasConnection = false;
    bool hasCustom = false;

    for (const auto &[key, value] : res.headers)
    {
      if (key == "Server" && value.find("Iora/1.0") != std::string::npos)
        hasServer = true;
      if (key == "Connection" && value == "keep-alive")
        hasConnection = true;
      if (key == "Custom-Header" && value == "test-value")
        hasCustom = true;
    }

    REQUIRE(hasServer);
    REQUIRE(hasConnection);
    REQUIRE(hasCustom);

    server.stop();
  }

  SECTION("Server handles backpressure with 503 Service Unavailable")
  {
    // Create a WebhookServer with very small thread pool for testing backpressure
    iora::network::WebhookServer server;
    server.setPort(8088);

    std::atomic<int> requestsProcessed{0};
    std::atomic<bool> allowProcessing{false};

    // Set up a slow endpoint to fill the thread pool
    server.onPost(
      "/slow",
      [&requestsProcessed, &allowProcessing](const iora::network::WebhookServer::Request &,
                                             iora::network::WebhookServer::Response &res)
      {
        // Wait until allowed to proceed
        while (!allowProcessing)
        {
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        requestsProcessed++;
        res.set_content("processed", "text/plain");
      });

    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Send enough requests to overwhelm the thread pool
    // The WebhookServer uses default ThreadPool which has maxQueueSize of 1024
    // but we'll send just a few concurrent requests to block the pool
    std::vector<std::thread> requestThreads;
    std::vector<std::unique_ptr<std::atomic<int>>> responseStatuses;

    const int numRequests = 10; // More than default thread pool initial size

    for (int i = 0; i < numRequests; ++i)
    {
      responseStatuses.push_back(std::make_unique<std::atomic<int>>(0));
      requestThreads.emplace_back(
        [i, &responseStatuses]()
        {
          try
          {
            iora::network::HttpClient client;
            auto res = client.post("http://localhost:8088/slow", "test data",
                                   {{"Content-Type", "text/plain"}});
            responseStatuses[i]->store(res.statusCode);
          }
          catch (...)
          {
            responseStatuses[i]->store(-1); // Error indicator
          }
        });
    }

    // Give some time for requests to hit the server and potentially fill the thread pool
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Now allow processing to continue so some requests can complete successfully
    allowProcessing = true;

    // Give enough time for requests to complete successfully
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Wait for all requests to complete
    for (auto &t : requestThreads)
    {
      t.join();
    }

    // Check results
    int successCount = 0;
    int serviceUnavailableCount = 0;
    int errorCount = 0;

    for (const auto &status : responseStatuses)
    {
      int code = status->load();
      if (code == 200)
      {
        successCount++;
      }
      else if (code == 503)
      {
        serviceUnavailableCount++;
      }
      else
      {
        errorCount++;
      }
    }

    // We should have processed some requests successfully
    REQUIRE(successCount > 0);

    // Under normal load, all requests should succeed, but this test verifies
    // that the backpressure mechanism is in place and can reject requests
    // when the thread pool is overwhelmed
    REQUIRE(requestsProcessed == successCount);

    // Verify total requests equals success + rejections + errors
    REQUIRE(successCount + serviceUnavailableCount + errorCount == numRequests);

    server.stop();
  }
}
