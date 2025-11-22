// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client_pool.hpp>
#include <iora/network/webhook_server.hpp>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace iora::test;
using namespace iora::network;

// ══════════════════════════════════════════════════════════════════════════
// Test Fixture: WebhookServer Setup
// ══════════════════════════════════════════════════════════════════════════

class HttpClientPoolTestFixture
{
public:
  HttpClientPoolTestFixture()
  {
    server.setPort(8082);

    // Simple GET endpoint
    server.onGet("/test-get",
                 [](const WebhookServer::Request &, WebhookServer::Response &res)
                 {
                   res.set_content("{\"status\":\"ok\"}", "application/json");
                   res.status = 200;
                 });

    // Echo POST endpoint
    server.onPost("/test-post",
                  [](const WebhookServer::Request &req, WebhookServer::Response &res)
                  {
                    res.set_content(req.body, "application/json");
                    res.status = 200;
                  });

    // Slow endpoint for timeout testing
    server.onGet("/test-slow",
                 [](const WebhookServer::Request &, WebhookServer::Response &res)
                 {
                   std::this_thread::sleep_for(std::chrono::milliseconds(500));
                   res.set_content("{\"status\":\"slow\"}", "application/json");
                   res.status = 200;
                 });

    // Counter endpoint for concurrent testing
    server.onPost("/test-counter",
                  [this](const WebhookServer::Request &req, WebhookServer::Response &res)
                  {
                    requestCounter.fetch_add(1);
                    res.set_content("{\"received\":\"" + req.body + "\"}", "application/json");
                    res.status = 200;
                  });

    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
  }

  ~HttpClientPoolTestFixture()
  {
    server.stop();
  }

  WebhookServer server;
  std::atomic<int> requestCounter{0};
};

// ══════════════════════════════════════════════════════════════════════════
// Test: Basic Pool Operations
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool basic operations", "[http_client_pool][basic]")
{
  HttpClientPoolTestFixture fixture;

  HttpClientPool::Config config;
  config.poolSize = 5;
  config.requestTimeout = std::chrono::seconds(5);
  config.connectionTimeout = std::chrono::seconds(2);

  HttpClientPool pool(config);

  SECTION("Pool initializes with correct capacity")
  {
    REQUIRE(pool.capacity() == 5);
    REQUIRE(pool.available() == 5);
    REQUIRE(pool.inUse() == 0);
    REQUIRE(pool.full());
    REQUIRE_FALSE(pool.empty());
  }

  SECTION("Can acquire and use client")
  {
    auto client = pool.get();
    REQUIRE(client.isValid());
    REQUIRE(pool.available() == 4);
    REQUIRE(pool.inUse() == 1);

    auto response = client.get("http://localhost:8082/test-get");
    REQUIRE(response.success());
    REQUIRE(response.statusCode == 200);
  }

  SECTION("Client automatically returns to pool on scope exit")
  {
    {
      auto client = pool.get();
      REQUIRE(pool.inUse() == 1);
      REQUIRE(pool.available() == 4);
    } // Client destroyed here

    REQUIRE(pool.inUse() == 0);
    REQUIRE(pool.available() == 5);
  }

  SECTION("Can acquire multiple clients")
  {
    auto client1 = pool.get();
    auto client2 = pool.get();
    auto client3 = pool.get();

    REQUIRE(pool.inUse() == 3);
    REQUIRE(pool.available() == 2);

    // All clients work independently
    auto res1 = client1.get("http://localhost:8082/test-get");
    auto res2 = client2.get("http://localhost:8082/test-get");
    auto res3 = client3.get("http://localhost:8082/test-get");

    REQUIRE(res1.success());
    REQUIRE(res2.success());
    REQUIRE(res3.success());
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: RAII Behavior
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool RAII behavior", "[http_client_pool][raii]")
{
  HttpClientPoolTestFixture fixture;

  HttpClientPool::Config config;
  config.poolSize = 3;
  HttpClientPool pool(config);

  SECTION("Move constructor transfers ownership")
  {
    auto client1 = pool.get();
    REQUIRE(pool.inUse() == 1);

    auto client2 = std::move(client1);
    REQUIRE(pool.inUse() == 1);
    REQUIRE_FALSE(client1.isValid());
    REQUIRE(client2.isValid());
  }

  SECTION("Move assignment transfers ownership")
  {
    auto client1 = pool.get();
    auto client2 = pool.get();
    REQUIRE(pool.inUse() == 2);

    client1 = std::move(client2);
    REQUIRE(pool.inUse() == 1); // client1's original was returned
    REQUIRE_FALSE(client2.isValid());
    REQUIRE(client1.isValid());
  }

  SECTION("Moved-from client is invalid")
  {
    auto client = pool.get();
    REQUIRE(client.isValid());

    auto moved = std::move(client);
    REQUIRE(moved.isValid());
    REQUIRE_FALSE(client.isValid());
  }

  SECTION("Multiple operations on same client")
  {
    auto client = pool.get();

    auto res1 = client.get("http://localhost:8082/test-get");
    REQUIRE(res1.success());

    auto res2 = client.post("http://localhost:8082/test-post", "{\"data\":\"test\"}");
    REQUIRE(res2.success());

    // Client still in use
    REQUIRE(pool.inUse() == 1);
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Pool Exhaustion and Blocking
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool exhaustion and blocking", "[http_client_pool][blocking]")
{
  HttpClientPoolTestFixture fixture;

  HttpClientPool::Config config;
  config.poolSize = 2;
  HttpClientPool pool(config);

  SECTION("Blocks when pool is exhausted")
  {
    auto client1 = pool.get();
    auto client2 = pool.get();
    REQUIRE(pool.empty());

    std::atomic<bool> getCompleted{false};
    std::thread waiter(
      [&]()
      {
        auto client3 = pool.get();
        getCompleted = true;
      });

    // Give waiter time to block
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    REQUIRE_FALSE(getCompleted.load());

    // Return a client
    client1 = PooledHttpClient(std::move(client2)); // Returns client1's original

    waiter.join();
    REQUIRE(getCompleted.load());
  }

  SECTION("tryGet returns nullopt when pool exhausted")
  {
    auto client1 = pool.get();
    auto client2 = pool.get();

    auto result = pool.tryGet();
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("get with timeout returns nullopt on timeout")
  {
    auto client1 = pool.get();
    auto client2 = pool.get();

    auto start = std::chrono::steady_clock::now();
    auto result = pool.get(std::chrono::milliseconds(100));
    auto elapsed = std::chrono::steady_clock::now() - start;

    REQUIRE_FALSE(result.has_value());
    REQUIRE(elapsed >= std::chrono::milliseconds(100));
    REQUIRE(elapsed < std::chrono::milliseconds(200));
  }

  SECTION("get with timeout succeeds when client becomes available")
  {
    auto client1 = pool.get();
    auto client2 = pool.get();

    // Thread that returns client after delay
    std::thread returner(
      [&]()
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        client1 = PooledHttpClient(std::move(client2));
      });

    auto result = pool.get(std::chrono::milliseconds(200));
    REQUIRE(result.has_value());
    REQUIRE(result->isValid());

    returner.join();
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Multi-threaded Concurrent Access
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool concurrent access", "[http_client_pool][concurrent]")
{
  HttpClientPoolTestFixture fixture;

  HttpClientPool::Config config;
  config.poolSize = 10;
  HttpClientPool pool(config);

  SECTION("Multiple threads can acquire and use clients")
  {
    const int numThreads = 20;
    const int requestsPerThread = 10;
    std::atomic<int> successCount{0};
    std::atomic<int> failureCount{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i)
    {
      threads.emplace_back(
        [&, i]()
        {
          for (int j = 0; j < requestsPerThread; ++j)
          {
            try
            {
              auto client = pool.get();
              auto response = client.post("http://localhost:8082/test-counter",
                                          std::to_string(i * requestsPerThread + j));
              if (response.success())
              {
                successCount++;
              }
              else
              {
                failureCount++;
              }
            }
            catch (...)
            {
              failureCount++;
            }
          }
        });
    }

    for (auto &t : threads)
    {
      t.join();
    }

    REQUIRE(successCount.load() == numThreads * requestsPerThread);
    REQUIRE(failureCount.load() == 0);
    REQUIRE(fixture.requestCounter.load() == numThreads * requestsPerThread);
    REQUIRE(pool.available() == pool.capacity()); // All returned
  }

  SECTION("Concurrent tryGet under high contention")
  {
    const int numThreads = 50;
    std::atomic<int> successfulGets{0};
    std::atomic<int> failedGets{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i)
    {
      threads.emplace_back(
        [&]()
        {
          for (int j = 0; j < 10; ++j)
          {
            if (auto client = pool.tryGet())
            {
              successfulGets++;
              std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            else
            {
              failedGets++;
            }
            std::this_thread::yield();
          }
        });
    }

    for (auto &t : threads)
    {
      t.join();
    }

    REQUIRE(successfulGets.load() > 0);
    REQUIRE((successfulGets.load() + failedGets.load()) == numThreads * 10);
    REQUIRE(pool.available() == pool.capacity()); // All returned
  }

  SECTION("Stress test with rapid acquire/release")
  {
    const int numThreads = 8;
    std::atomic<bool> stopFlag{false};
    std::atomic<int> operationCount{0};

    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i)
    {
      threads.emplace_back(
        [&]()
        {
          while (!stopFlag.load())
          {
            if (auto client = pool.tryGet())
            {
              operationCount++;
              // Minimal work
              std::this_thread::yield();
            }
          }
        });
    }

    // Run for short duration
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    stopFlag = true;

    for (auto &t : threads)
    {
      t.join();
    }

    REQUIRE(operationCount.load() > 0);
    REQUIRE(pool.available() == pool.capacity());
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Statistics and Monitoring
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool statistics", "[http_client_pool][stats]")
{
  HttpClientPoolTestFixture fixture;

  HttpClientPool::Config config;
  config.poolSize = 10;
  HttpClientPool pool(config);

  SECTION("Statistics update correctly")
  {
    REQUIRE(pool.capacity() == 10);
    REQUIRE(pool.available() == 10);
    REQUIRE(pool.inUse() == 0);
    REQUIRE(pool.utilization() == 0.0);

    auto client1 = pool.get();
    REQUIRE(pool.available() == 9);
    REQUIRE(pool.inUse() == 1);
    REQUIRE(pool.utilization() == 10.0);

    auto client2 = pool.get();
    auto client3 = pool.get();
    REQUIRE(pool.available() == 7);
    REQUIRE(pool.inUse() == 3);
    REQUIRE(pool.utilization() == 30.0);

    client1 = PooledHttpClient(std::move(client2));
    REQUIRE(pool.available() == 8);
    REQUIRE(pool.inUse() == 2);
    REQUIRE(pool.utilization() == 20.0);
  }

  SECTION("empty() and full() work correctly")
  {
    REQUIRE(pool.full());
    REQUIRE_FALSE(pool.empty());

    std::vector<PooledHttpClient> clients;
    for (std::size_t i = 0; i < pool.capacity(); ++i)
    {
      clients.push_back(pool.get());
    }

    REQUIRE(pool.empty());
    REQUIRE_FALSE(pool.full());

    clients.clear();

    REQUIRE(pool.full());
    REQUIRE_FALSE(pool.empty());
  }

  SECTION("Config accessor returns correct configuration")
  {
    const auto &cfg = pool.config();
    REQUIRE(cfg.poolSize == 10);
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Close Operations
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool close behavior", "[http_client_pool][close]")
{
  HttpClientPoolTestFixture fixture;

  HttpClientPool::Config config;
  config.poolSize = 5;
  HttpClientPool pool(config);

  SECTION("Close prevents new acquisitions")
  {
    pool.close();
    REQUIRE(pool.isClosed());

    REQUIRE_THROWS_AS(pool.get(), std::runtime_error);
  }

  SECTION("Close wakes blocked threads")
  {
    auto client1 = pool.get();
    auto client2 = pool.get();
    auto client3 = pool.get();
    auto client4 = pool.get();
    auto client5 = pool.get();

    std::atomic<bool> getCompleted{false};
    std::atomic<bool> gotException{false};

    std::thread waiter(
      [&]()
      {
        try
        {
          auto client = pool.get();
        }
        catch (const std::runtime_error &)
        {
          gotException = true;
        }
        getCompleted = true;
      });

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    REQUIRE_FALSE(getCompleted.load());

    pool.close();

    waiter.join();
    REQUIRE(getCompleted.load());
    REQUIRE(gotException.load());
  }

  SECTION("tryGet returns nullopt after close")
  {
    pool.close();

    auto result = pool.tryGet();
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("get with timeout returns nullopt after close")
  {
    pool.close();

    auto result = pool.get(std::chrono::seconds(1));
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Existing clients work after close")
  {
    auto client = pool.get();
    pool.close();

    // Client can still be used
    auto response = client.get("http://localhost:8082/test-get");
    REQUIRE(response.success());
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: HTTP Operations Through Pool
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool HTTP operations", "[http_client_pool][http]")
{
  HttpClientPoolTestFixture fixture;

  HttpClientPool::Config config;
  config.poolSize = 3;
  HttpClientPool pool(config);

  SECTION("GET request through pooled client")
  {
    auto client = pool.get();
    auto response = client.get("http://localhost:8082/test-get");

    REQUIRE(response.success());
    REQUIRE(response.statusCode == 200);
    REQUIRE(response.body.find("\"status\":\"ok\"") != std::string::npos);
  }

  SECTION("POST request through pooled client")
  {
    auto client = pool.get();
    std::string body = "{\"test\":\"data\"}";
    auto response = client.post("http://localhost:8082/test-post", body);

    REQUIRE(response.success());
    REQUIRE(response.body == body);
  }

  SECTION("postJson through pooled client")
  {
    auto client = pool.get();
    auto payload = iora::parsers::Json::object();
    payload["message"] = "hello";

    auto response = client.postJson("http://localhost:8082/test-post", payload);
    REQUIRE(response.success());

    auto json = HttpClient::parseJsonOrThrow(response);
    REQUIRE(json["message"] == "hello");
  }

  SECTION("Multiple requests with same pooled client")
  {
    auto client = pool.get();

    auto res1 = client.get("http://localhost:8082/test-get");
    REQUIRE(res1.success());

    auto res2 = client.post("http://localhost:8082/test-post", "test");
    REQUIRE(res2.success());

    auto res3 = client.get("http://localhost:8082/test-get");
    REQUIRE(res3.success());
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Configuration
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool configuration", "[http_client_pool][config]")
{
  SECTION("Constructor throws on zero pool size")
  {
    HttpClientPool::Config config;
    config.poolSize = 0;

    REQUIRE_THROWS_AS(HttpClientPool(config), std::invalid_argument);
  }

  SECTION("Custom configuration applied to clients")
  {
    HttpClientPool::Config config;
    config.poolSize = 2;
    config.userAgent = "CustomAgent/1.0";
    config.requestTimeout = std::chrono::seconds(10);

    HttpClientPool pool(config);

    REQUIRE(pool.config().userAgent == "CustomAgent/1.0");
    REQUIRE(pool.config().requestTimeout == std::chrono::seconds(10));
  }

  SECTION("Default headers configuration")
  {
    HttpClientPool::Config config;
    config.poolSize = 2;
    config.defaultHeaders = {{"X-Custom-Header", "test-value"}};

    HttpClientPool pool(config);
    REQUIRE(pool.config().defaultHeaders.size() == 1);
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: Edge Cases
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool edge cases", "[http_client_pool][edge]")
{
  HttpClientPoolTestFixture fixture;

  SECTION("Pool with size 1 works correctly")
  {
    HttpClientPool::Config config;
    config.poolSize = 1;
    HttpClientPool pool(config);

    auto client = pool.get();
    REQUIRE(pool.empty());

    auto response = client.get("http://localhost:8082/test-get");
    REQUIRE(response.success());
  }

  SECTION("Large pool size")
  {
    HttpClientPool::Config config;
    config.poolSize = 100;
    HttpClientPool pool(config);

    REQUIRE(pool.capacity() == 100);
    REQUIRE(pool.available() == 100);

    std::vector<PooledHttpClient> clients;
    for (int i = 0; i < 50; ++i)
    {
      clients.push_back(pool.get());
    }

    REQUIRE(pool.inUse() == 50);
    REQUIRE(pool.available() == 50);
  }

  SECTION("Rapid acquire and release in single thread")
  {
    HttpClientPool::Config config;
    config.poolSize = 5;
    HttpClientPool pool(config);

    for (int i = 0; i < 100; ++i)
    {
      auto client = pool.get();
      // Client immediately goes out of scope
    }

    REQUIRE(pool.available() == pool.capacity());
  }
}

// ══════════════════════════════════════════════════════════════════════════
// Test: High Concurrency - 1000 Connections
// ══════════════════════════════════════════════════════════════════════════

TEST_CASE("HttpClientPool 1000 concurrent connections with 200 OK", "[http_client_pool][high_concurrency]")
{
  HttpClientPoolTestFixture fixture;

  HttpClientPool::Config config;
  config.poolSize = 100; // Pool size for optimal concurrency
  config.requestTimeout = std::chrono::seconds(5);
  config.connectionTimeout = std::chrono::seconds(2); // Adequate timeout for high concurrency
  HttpClientPool pool(config);

  SECTION("1000 connections complete with 200 OK within 10 seconds")
  {
    const int totalConnections = 1000;
    const int numThreads = 100; // Number of worker threads
    const int connectionsPerThread = totalConnections / numThreads;

    std::atomic<int> successCount{0};
    std::atomic<int> failureCount{0};
    std::atomic<int> non200Count{0};
    std::atomic<int> exceptionCount{0};
    std::mutex exceptionMutex;
    std::vector<std::string> exceptionMessages;

    // Start timing
    auto startTime = std::chrono::steady_clock::now();

    // Launch worker threads
    std::vector<std::thread> threads;
    threads.reserve(numThreads);

    for (int i = 0; i < numThreads; ++i)
    {
      threads.emplace_back(
        [&, threadId = i]()
        {
          for (int j = 0; j < connectionsPerThread; ++j)
          {
            bool requestSucceeded = false;
            int retries = 0;
            const int maxRetries = 3;

            while (!requestSucceeded && retries < maxRetries)
            {
              try
              {
                auto client = pool.get();
                if (!client.isValid())
                {
                  failureCount++;
                  break;
                }

                auto response = client.get("http://localhost:8082/test-get");

                if (response.success())
                {
                  if (response.statusCode == 200)
                  {
                    successCount++;
                    requestSucceeded = true;
                  }
                  else
                  {
                    non200Count++;
                    requestSucceeded = true;
                  }
                }
                else
                {
                  failureCount++;
                  requestSucceeded = true;
                }
              }
              catch (const std::exception &e)
              {
                std::string errMsg(e.what());
                // Retry on localhost connection timeout (transient under high concurrency)
                if (errMsg.find("Localhost connection taking too long") != std::string::npos && retries < maxRetries - 1)
                {
                  retries++;
                  continue;
                }

                exceptionCount++;
                std::lock_guard<std::mutex> lock(exceptionMutex);
                if (exceptionMessages.size() < 10)
                {
                  exceptionMessages.push_back(e.what());
                }
                requestSucceeded = true; // Exit retry loop
              }
              catch (...)
              {
                exceptionCount++;
                std::lock_guard<std::mutex> lock(exceptionMutex);
                if (exceptionMessages.size() < 10)
                {
                  exceptionMessages.push_back("Unknown exception");
                }
                requestSucceeded = true; // Exit retry loop
              }
            }
          }
        });
    }

    // Wait for all threads to complete
    for (auto &t : threads)
    {
      t.join();
    }

    // Calculate elapsed time
    auto endTime = std::chrono::steady_clock::now();
    auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();

    // Print diagnostic info if there are failures
    int totalProcessed = successCount.load() + failureCount.load() + non200Count.load() + exceptionCount.load();

    std::cout << "=== Test Results ===" << std::endl;
    std::cout << "Success: " << successCount.load() << std::endl;
    std::cout << "Failures: " << failureCount.load() << std::endl;
    std::cout << "Non-200: " << non200Count.load() << std::endl;
    std::cout << "Exceptions: " << exceptionCount.load() << std::endl;
    std::cout << "Total Processed: " << totalProcessed << " / " << totalConnections << std::endl;
    std::cout << "Elapsed: " << elapsedSeconds << " seconds" << std::endl;
    if (!exceptionMessages.empty())
    {
      std::cout << "Exception samples:" << std::endl;
      for (const auto &msg : exceptionMessages)
      {
        std::cout << "  - " << msg << std::endl;
      }
    }
    std::cout << "===================" << std::endl;

    // Assertions
    REQUIRE(successCount.load() == totalConnections);
    REQUIRE(failureCount.load() == 0);
    REQUIRE(non200Count.load() == 0);
    REQUIRE(exceptionCount.load() == 0);
    REQUIRE(elapsedSeconds <= 10);
    REQUIRE(pool.available() == pool.capacity()); // All clients returned to pool
  }
}
