#include "iora/iora.hpp"
#include "catch2/catch_test_macros.hpp"

TEST_CASE("HttpClient and WebhookServer integration tests")
{
  iora::http::WebhookServer server;
  server.setPort(8081);

  server.onJsonPost("/test-post-json",
                    [](const iora::json::Json& input) -> iora::json::Json {
                      return {{"echo", input}};
                    });

  server.onJsonPost("/test-async",
                    [](const iora::json::Json& input) -> iora::json::Json {
                      return {{"async", true}, {"received", input}};
                    });

  server.onJsonGet("/test-get",
                   [](const iora::json::Json&) -> iora::json::Json {
                     return {{"status", "ok"}};
                   });

  server.onPost("/test-stream",
                [](const httplib::Request&, httplib::Response& res)
                {
                  res.set_content("data: {\"text\":\"line1\"}\n"
                                  "data: {\"text\":\"line2\"}\n"
                                  "data: [DONE]\n",
                                  "text/event-stream");
                  res.status = 200;
                });

  server.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  iora::http::HttpClient client;

  SECTION("GET request returns valid JSON")
  {
    try
    {
      auto res = client.get("http://localhost:8081/test-get");
      REQUIRE(res["status"] == "ok");
    }
    catch (const std::exception& ex)
    {
      FAIL(std::string("Exception: ") + ex.what());
    }
  }

  SECTION("POST JSON request with payload")
  {
    iora::json::Json payload = {{"message", "hello"}};
    auto res = client.postJson("http://localhost:8081/test-post-json", payload);
    REQUIRE(res["echo"]["message"] == "hello");
  }

  SECTION("Async POST JSON returns future")
  {
    iora::json::Json payload = {{"async_test", 1}};
    std::future<iora::json::Json> future =
        client.postJsonAsync("http://localhost:8081/test-async", payload);
    auto res = future.get();
    REQUIRE(res["async"] == true);
    REQUIRE(res["received"]["async_test"] == 1);
  }

  SECTION("Streamed POST returns line chunks")
  {
    iora::json::Json payload = {{}};
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

constexpr const char* TEST_CERT_PATH = "/workspace/iora/tests/tls-certs/test_tls_cert.pem";
constexpr const char* TEST_KEY_PATH = "/workspace/iora/tests/tls-certs/test_tls_key.pem";

TEST_CASE("WebhookServer TLS (SSL) basic functionality", "[webhookserver][tls]")
{
  const std::string certFile = TEST_CERT_PATH;
  const std::string keyFile = TEST_KEY_PATH;

  if (!std::filesystem::exists(certFile) || !std::filesystem::exists(keyFile)) {
    WARN("Skipping TLS test: cert or key file not found");
    return;
  }

  iora::http::WebhookServer server;
  server.setPort(8443);

  iora::http::WebhookServer::TlsConfig tlsCfg;
  tlsCfg.certFile = certFile;
  tlsCfg.keyFile = keyFile;
  tlsCfg.requireClientCert = false;

  REQUIRE_NOTHROW(server.enableTls(tlsCfg));

  server.onJsonGet("/tls-test", [](const iora::json::Json&) -> iora::json::Json {
    return {{"tls", true}};
  });

  REQUIRE_NOTHROW(server.start());
  std::this_thread::sleep_for(std::chrono::milliseconds(1500));

  SECTION("HTTPS GET returns valid JSON over TLS")
  {
    cpr::Session session;
    session.SetUrl(cpr::Url{"https://localhost:8443/tls-test"});
    session.SetVerifySsl(false); // self-signed cert
    auto response = session.Get();

    REQUIRE(response.status_code == 200);
    auto json = iora::http::HttpClient::parseJsonOrThrow(response);
    REQUIRE(json["tls"] == true);
  }

  server.stop();
}
