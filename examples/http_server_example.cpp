// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// iora flagship example: an HTTP/1.1 server end to end in one process.
//
// Constructs an HttpServer bound to a fixed loopback port, registers three routes
// exercising the headline routing API -- a GET returning JSON, a POST that echoes
// the request body, and a GET with a named path parameter -- starts the server, and
// then makes real requests against it with iora's HttpClient to prove it works. It
// mirrors transport_example.cpp: self-request, verify, then orderly teardown.
//
// This program is built in CI (BUILD_EXAMPLES=ON): a broken headline API breaks the
// build. It is the flagship snippet referenced from docs/network/http_server.md.
//
// NOTE: http_server.hpp transitively includes transport_impl.hpp, which carries the
// out-of-line Transport method definitions and MUST be included in EXACTLY ONE
// translation unit. This is that TU.

#include "iora/network/http_client.hpp"
#include "iora/network/http_server.hpp"
#include "iora/parsers/json.hpp"

#include <iostream>
#include <string>

using iora::network::HttpClient;
using iora::network::HttpServer;
using iora::parsers::Json;

int main()
{
  const std::string bindIp = "127.0.0.1";
  const int port = 18095; // fixed loopback port for the demo

  // ===== Server: register a few routes over the real HttpServer API. =====
  HttpServer server(bindIp, port);

  // GET returning JSON. set_content sets both the body and Content-Type/Length.
  server.onGet("/api/info",
               [](const HttpServer::Request &, HttpServer::Response &res)
               {
                 Json info = Json::object();
                 info["service"] = "iora-http-example";
                 info["ok"] = true;
                 res.set_content(info.dump(), "application/json");
               });

  // POST echoing the request body straight back to the caller.
  server.onPost("/echo",
                [](const HttpServer::Request &req, HttpServer::Response &res)
                { res.set_content(req.body, "text/plain"); });

  // Named path segment -> captured (raw) into req.params.
  server.onGet("/users/:id",
               [](const HttpServer::Request &req, HttpServer::Response &res)
               { res.set_content("user " + req.params.at("id"), "text/plain"); });

  // start() adds the listener synchronously and throws on a bind failure (e.g. the
  // port is already in use).
  try
  {
    server.start();
  }
  catch (const std::exception &ex)
  {
    std::cerr << "server start failed: " << ex.what() << "\n";
    return 1;
  }

  // ===== Client: make real requests against the server and verify. =====
  HttpClient client; // default Config: 2 s connect / 3 s request timeouts

  const std::string base = "http://" + bindIp + ":" + std::to_string(port);
  int rc = 0;

  try
  {
    // 1) GET the JSON route.
    HttpClient::Response info = client.get(base + "/api/info");
    std::cout << "GET /api/info -> " << info.statusCode << " " << info.body << "\n";
    if (!info.success() || info.body.find("iora-http-example") == std::string::npos)
    {
      std::cerr << "GET /api/info did not return the expected JSON\n";
      rc = 1;
    }

    // 2) POST a body and expect it echoed verbatim.
    const std::string payload = "hello iora http";
    HttpClient::Response echo = client.post(base + "/echo", payload);
    std::cout << "POST /echo -> " << echo.statusCode << " \"" << echo.body << "\"\n";
    if (!echo.success() || echo.body != payload)
    {
      std::cerr << "POST /echo mismatch: expected \"" << payload << "\", got \"" << echo.body
                << "\"\n";
      rc = 1;
    }

    // 3) GET a path-parameter route.
    HttpClient::Response user = client.get(base + "/users/42");
    std::cout << "GET /users/42 -> " << user.statusCode << " \"" << user.body << "\"\n";
    if (!user.success() || user.body != "user 42")
    {
      std::cerr << "GET /users/42 mismatch: expected \"user 42\", got \"" << user.body << "\"\n";
      rc = 1;
    }
  }
  catch (const std::exception &ex)
  {
    std::cerr << "http request failed: " << ex.what() << "\n";
    rc = 1;
  }

  // Orderly teardown: stop the server (drains in-flight handlers) before scope exit.
  server.stop();

  if (rc == 0)
  {
    std::cout << "http server round-trip OK\n";
  }
  return rc;
}
