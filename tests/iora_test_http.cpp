// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "test_helpers.hpp"

using namespace iora::test;

TEST_CASE("HttpClient and WebhookServer integration tests")
{
  iora::network::WebhookServer server;
  server.setPort(8081);

  server.onJsonPost("/test-post-json",
                    [](const iora::parsers::Json& input) -> iora::parsers::Json
                    {
                      auto obj = iora::parsers::Json::object();
                      obj["echo"] = input;
                      return obj;
                    });

  server.onJsonPost("/test-async",
                    [](const iora::parsers::Json& input) -> iora::parsers::Json
                    {
                      auto obj = iora::parsers::Json::object();
                      obj["async"] = true;
                      obj["received"] = input;
                      return obj;
                    });

  server.onJsonGet("/test-get",
                   [](const iora::parsers::Json&) -> iora::parsers::Json
                   {
                     auto obj = iora::parsers::Json::object();
                     obj["status"] = "ok";
                     return obj;
                   });

  server.onPost("/test-stream",
                [](const iora::network::WebhookServer::Request&,
                   iora::network::WebhookServer::Response& res)
                {
                  res.set_content("data: {\"text\":\"line1\"}\n"
                                  "data: {\"text\":\"line2\"}\n"
                                  "data: [DONE]\n",
                                  "text/event-stream");
                  res.status = 200;
                });

  server.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  iora::network::HttpClient client;

  SECTION("GET request returns valid JSON")
  {
    try
    {
      auto res = client.get("http://localhost:8081/test-get");
      REQUIRE(res.success());
      auto json = iora::network::HttpClient::parseJsonOrThrow(res);
      REQUIRE(json["status"] == "ok");
    }
    catch (const std::exception& ex)
    {
      FAIL(std::string("Exception: ") + ex.what());
    }
  }

  SECTION("POST JSON request with payload")
  {
    auto payload = iora::parsers::Json::object();
    payload["message"] = "hello";
    auto res = client.postJson("http://localhost:8081/test-post-json", payload);
    REQUIRE(res.success());
    auto json = iora::network::HttpClient::parseJsonOrThrow(res);
    REQUIRE(json["echo"]["message"] == "hello");
  }

  SECTION("Async POST JSON returns future")
  {
    auto payload = iora::parsers::Json::object();
    payload["async_test"] = 1;
    std::future<iora::network::HttpClient::Response> future =
        client.postJsonAsync("http://localhost:8081/test-async", payload);
    auto res = future.get();
    REQUIRE(res.success());
    auto json = iora::network::HttpClient::parseJsonOrThrow(res);
    REQUIRE(json["async"] == true);
    REQUIRE(json["received"]["async_test"] == 1);
  }

  SECTION("Streamed POST returns line chunks")
  {
    auto payload = iora::parsers::Json::object();
    std::vector<std::string> chunks;
    client.postStream("http://localhost:8081/test-stream", payload, {},
                      [&](const std::string& line)
                      {
                        if (!line.empty())
                        {
                          chunks.push_back(line);
                        }
                      });

    REQUIRE(chunks.size() == 3);
    REQUIRE(chunks[0] == "data: {\"text\":\"line1\"}");
    REQUIRE(chunks[1] == "data: {\"text\":\"line2\"}");
    REQUIRE(chunks[2] == "data: [DONE]");
  }

  server.stop();
}

// BSD socket tests for HTTP client timeout behavior
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include <thread>

TEST_CASE("HTTP Client BSD Socket Timeout Tests", "[http][timeout][bsd]")
{
  using namespace iora::network;

  // Helper function to create a listening BSD socket
  auto createListeningSocket = [](uint16_t port) -> int
  {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
      throw std::runtime_error("Failed to create socket");
    }

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    {
      close(sockfd);
      throw std::runtime_error("Failed to bind socket");
    }

    if (listen(sockfd, 1) < 0)
    {
      close(sockfd);
      throw std::runtime_error("Failed to listen on socket");
    }

    // Set non-blocking mode
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    return sockfd;
  };

  SECTION("Test 1: Write timeout - accept but don't respond")
  {
    uint16_t port = 18901;
    int listenSock = createListeningSocket(port);

    std::atomic<bool> shouldAccept{true};
    std::thread acceptThread(
        [listenSock, &shouldAccept]()
        {
          while (shouldAccept)
          {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientSock =
                accept(listenSock, (struct sockaddr*) &clientAddr, &clientLen);
            if (clientSock >= 0)
            {
              // Accept connection but don't send any response
              // Just hold the connection open
              std::this_thread::sleep_for(std::chrono::seconds(10));
              close(clientSock);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          }
        });

    // Give the accept thread time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    HttpClient::Config config;
    config.requestTimeout = std::chrono::milliseconds(2000); // 2 second timeout
    HttpClient clientWithTimeout(config);

    auto startTime = std::chrono::steady_clock::now();
    bool timedOut = false;

    try
    {
      auto response = clientWithTimeout.get(
          "http://127.0.0.1:" + std::to_string(port) + "/test");
      FAIL("Should have timed out");
    }
    catch (const std::exception& e)
    {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - startTime);

      // Should timeout within 2-3 seconds (allowing some overhead)
      REQUIRE(elapsed.count() < 3000);
      REQUIRE(elapsed.count() >=
              1900); // Should wait at least most of the timeout

      std::string error = e.what();
      // Check that it's a timeout error
      bool isTimeout = (error.find("timeout") != std::string::npos) ||
                       (error.find("Timeout") != std::string::npos);
      REQUIRE(isTimeout);
      timedOut = true;
    }

    REQUIRE(timedOut);

    shouldAccept = false;
    acceptThread.join();
    close(listenSock);
  }

  SECTION("Test 2: Instant disconnect - close on connect")
  {
    uint16_t port = 18902;
    int listenSock = createListeningSocket(port);

    std::atomic<bool> shouldAccept{true};
    std::thread acceptThread(
        [listenSock, &shouldAccept]()
        {
          while (shouldAccept)
          {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientSock =
                accept(listenSock, (struct sockaddr*) &clientAddr, &clientLen);
            if (clientSock >= 0)
            {
              // Immediately close the connection
              close(clientSock);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          }
        });

    // Give the accept thread time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    HttpClient client;

    auto startTime = std::chrono::steady_clock::now();
    bool disconnected = false;

    try
    {
      auto response =
          client.get("http://127.0.0.1:" + std::to_string(port) + "/test");
      FAIL("Should have been disconnected");
    }
    catch (const std::exception& e)
    {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - startTime);

      // Should fail almost immediately (within 1 second)
      REQUIRE(elapsed.count() < 1000);

      std::string error = e.what();
      // Check that it's a connection/disconnect error
      bool isDisconnect = (error.find("closed") != std::string::npos) ||
                          (error.find("Connection") != std::string::npos) ||
                          (error.find("disconnect") != std::string::npos);
      REQUIRE(isDisconnect);
      disconnected = true;
    }

    REQUIRE(disconnected);

    shouldAccept = false;
    acceptThread.join();
    close(listenSock);
  }

  SECTION("Test 3: Connection refused - bogus port")
  {
    uint16_t bogusPort = 19999; // Unlikely to be in use
    HttpClient client;

    auto startTime = std::chrono::steady_clock::now();
    bool refused = false;

    try
    {
      auto response =
          client.get("http://127.0.0.1:" + std::to_string(bogusPort) + "/test");
      FAIL("Should have been refused");
    }
    catch (const std::exception& e)
    {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - startTime);

      // Should fail immediately (within 500ms for local connection)
      REQUIRE(elapsed.count() < 500);

      std::string error = e.what();
      // Check that it's a connection refused error
      bool isRefused = (error.find("refused") != std::string::npos) ||
                       (error.find("Connection") != std::string::npos) ||
                       (error.find("Failed") != std::string::npos) ||
                       (error.find("taking too long") != std::string::npos) ||
                       (error.find("fail immediately") != std::string::npos);
      REQUIRE(isRefused);
      refused = true;
    }

    REQUIRE(refused);
  }
}

// TLS BSD socket tests for HTTP client timeout behavior
TEST_CASE("HTTPS Client BSD Socket Timeout Tests with TLS",
          "[https][timeout][bsd][tls]")
{
  using namespace iora::network;

  const std::string certFile =
      "/workspace/iora/tests/tls-certs/test_tls_cert.pem";
  const std::string keyFile =
      "/workspace/iora/tests/tls-certs/test_tls_key.pem";

  if (!std::filesystem::exists(certFile) || !std::filesystem::exists(keyFile))
  {
    WARN("Skipping TLS timeout tests: cert or key file not found");
    return;
  }

  // Helper to create TLS listening socket using OpenSSL
  auto createTlsListeningSocket = [&](uint16_t port) -> std::pair<int, SSL_CTX*>
  {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
      throw std::runtime_error("Failed to create SSL context");
    }

    if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) <=
        0)
    {
      SSL_CTX_free(ctx);
      throw std::runtime_error("Failed to load certificate");
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <=
        0)
    {
      SSL_CTX_free(ctx);
      throw std::runtime_error("Failed to load private key");
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
      SSL_CTX_free(ctx);
      throw std::runtime_error("Failed to create socket");
    }

    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    {
      close(sockfd);
      SSL_CTX_free(ctx);
      throw std::runtime_error("Failed to bind socket");
    }

    if (listen(sockfd, 1) < 0)
    {
      close(sockfd);
      SSL_CTX_free(ctx);
      throw std::runtime_error("Failed to listen on socket");
    }

    // Set non-blocking mode
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    return {sockfd, ctx};
  };

  SECTION("TLS Test 1: Write timeout - accept TLS but don't respond")
  {
    uint16_t port = 18911;
    auto [listenSock, sslCtx] = createTlsListeningSocket(port);

    std::atomic<bool> shouldAccept{true};
    std::thread acceptThread(
        [listenSock, sslCtx, &shouldAccept]()
        {
          while (shouldAccept)
          {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientSock =
                accept(listenSock, (struct sockaddr*) &clientAddr, &clientLen);
            if (clientSock >= 0)
            {
              SSL* ssl = SSL_new(sslCtx);
              SSL_set_fd(ssl, clientSock);

              // Perform TLS handshake
              if (SSL_accept(ssl) > 0)
              {
                // Handshake successful, but don't send any HTTP response
                // Just hold the connection open
                std::this_thread::sleep_for(std::chrono::seconds(10));
              }

              SSL_shutdown(ssl);
              SSL_free(ssl);
              close(clientSock);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          }
        });

    // Give the accept thread time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    HttpClient::Config config;
    config.requestTimeout = std::chrono::milliseconds(2000); // 2 second timeout
    HttpClient client(config);

    // Configure TLS to accept self-signed cert
    HttpClient::TlsConfig tlsCfg;
    tlsCfg.verifyPeer = false;
    client.setTlsConfig(tlsCfg);

    auto startTime = std::chrono::steady_clock::now();
    bool timedOut = false;

    try
    {
      auto response =
          client.get("https://127.0.0.1:" + std::to_string(port) + "/test");
      FAIL("Should have timed out");
    }
    catch (const std::exception& e)
    {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - startTime);

      // Should timeout within 2-3 seconds (allowing some overhead)
      REQUIRE(elapsed.count() < 3000);
      REQUIRE(elapsed.count() >=
              1900); // Should wait at least most of the timeout

      std::string error = e.what();
      bool isTimeout = (error.find("timeout") != std::string::npos) ||
                       (error.find("Timeout") != std::string::npos);
      REQUIRE(isTimeout);
      timedOut = true;
    }

    REQUIRE(timedOut);

    shouldAccept = false;
    acceptThread.join();
    close(listenSock);
    SSL_CTX_free(sslCtx);
  }

  SECTION("TLS Test 2: Instant disconnect - close after TLS handshake")
  {
    uint16_t port = 18912;
    auto [listenSock, sslCtx] = createTlsListeningSocket(port);

    std::atomic<bool> shouldAccept{true};
    std::thread acceptThread(
        [listenSock, sslCtx, &shouldAccept]()
        {
          while (shouldAccept)
          {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            int clientSock =
                accept(listenSock, (struct sockaddr*) &clientAddr, &clientLen);
            if (clientSock >= 0)
            {
              SSL* ssl = SSL_new(sslCtx);
              SSL_set_fd(ssl, clientSock);

              // Perform TLS handshake then immediately close
              if (SSL_accept(ssl) > 0)
              {
                // Immediately close after handshake
                SSL_shutdown(ssl);
              }

              SSL_free(ssl);
              close(clientSock);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          }
        });

    // Give the accept thread time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    HttpClient client;

    // Configure TLS to accept self-signed cert
    HttpClient::TlsConfig tlsCfg;
    tlsCfg.verifyPeer = false;
    client.setTlsConfig(tlsCfg);

    auto startTime = std::chrono::steady_clock::now();
    bool disconnected = false;

    try
    {
      auto response =
          client.get("https://127.0.0.1:" + std::to_string(port) + "/test");
      FAIL("Should have been disconnected");
    }
    catch (const std::exception& e)
    {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - startTime);

      // Should fail within 2 seconds (TLS handshake + disconnect)
      REQUIRE(elapsed.count() < 2000);

      std::string error = e.what();
      bool isDisconnect = (error.find("closed") != std::string::npos) ||
                          (error.find("Connection") != std::string::npos) ||
                          (error.find("disconnect") != std::string::npos) ||
                          (error.find("TLS") != std::string::npos);
      REQUIRE(isDisconnect);
      disconnected = true;
    }

    REQUIRE(disconnected);

    shouldAccept = false;
    acceptThread.join();
    close(listenSock);
    SSL_CTX_free(sslCtx);
  }

  SECTION("TLS Test 3: Connection refused - bogus TLS port")
  {
    uint16_t bogusPort = 19998; // Unlikely to be in use
    HttpClient client;

    // Configure TLS
    HttpClient::TlsConfig tlsCfg;
    tlsCfg.verifyPeer = false;
    client.setTlsConfig(tlsCfg);

    auto startTime = std::chrono::steady_clock::now();
    bool refused = false;

    try
    {
      auto response = client.get(
          "https://127.0.0.1:" + std::to_string(bogusPort) + "/test");
      FAIL("Should have been refused");
    }
    catch (const std::exception& e)
    {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - startTime);

      // Should fail immediately (within 500ms for local connection)
      REQUIRE(elapsed.count() < 500);

      std::string error = e.what();
      bool isRefused = (error.find("refused") != std::string::npos) ||
                       (error.find("Connection") != std::string::npos) ||
                       (error.find("Failed") != std::string::npos) ||
                       (error.find("fail immediately") != std::string::npos);
      REQUIRE(isRefused);
      refused = true;
    }

    REQUIRE(refused);
  }
}

constexpr const char* TEST_CERT_PATH =
    "/workspace/iora/tests/tls-certs/test_tls_cert.pem";
constexpr const char* TEST_KEY_PATH =
    "/workspace/iora/tests/tls-certs/test_tls_key.pem";

TEST_CASE("WebhookServer TLS (SSL) basic functionality", "[webhookserver][tls]")
{
  const std::string certFile =
      "/workspace/iora/tests/tls-certs/test_tls_cert.pem";
  const std::string keyFile =
      "/workspace/iora/tests/tls-certs/test_tls_key.pem";

  if (!std::filesystem::exists(certFile) || !std::filesystem::exists(keyFile))
  {
    WARN("Skipping TLS test: cert or key file not found");
    return;
  }

  iora::network::WebhookServer server;
  server.setPort(8443);

  iora::network::WebhookServer::TlsConfig tlsCfg;
  tlsCfg.certFile = certFile;
  tlsCfg.keyFile = keyFile;
  tlsCfg.requireClientCert = false;

  REQUIRE_NOTHROW(server.enableTls(tlsCfg));

  server.onJsonGet("/tls-test",
                   [](const iora::parsers::Json&) -> iora::parsers::Json
                   {
                     auto obj = iora::parsers::Json::object();
                     obj["tls"] = true;
                     return obj;
                   });

  REQUIRE_NOTHROW(server.start());
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));

  SECTION("HTTPS GET returns valid JSON over TLS")
  {
    iora::network::HttpClient client;
    // Accept self-signed cert for test
    iora::network::HttpClient::TlsConfig tlsCfg;
    tlsCfg.verifyPeer = false;
    client.setTlsConfig(tlsCfg);
    try
    {
      auto res = client.get("https://localhost:8443/tls-test");
      REQUIRE(res.success());
      auto json = iora::network::HttpClient::parseJsonOrThrow(res);
      REQUIRE(json["tls"] == true);
    }
    catch (const std::exception& ex)
    {
      FAIL(std::string("Exception: ") + ex.what());
    }
  }

  server.stop();
}

// BSD socket tests for HTTP client timeout behavior
