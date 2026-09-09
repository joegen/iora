// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// iora flagship example: JSON-RPC 2.0 over HTTP, end-to-end in one process.
//
// Composes network::HttpServer + rpc::JsonRpcServer + rpc::JsonRpcHttpEndpoint +
// rpc::JsonRpcClient and performs a real request round trip over a bound loopback
// port. It also enables the negotiated gzip content-coding path in BOTH directions
// (see the compressionThreshold comments) so the headline compression path is
// exercised when the program runs.
//
// This program is built in CI (BUILD_EXAMPLES=ON): a broken headline API breaks the
// build. It is the flagship snippet referenced from docs/rpc/jsonrpc.md.

#include "iora/core/thread_pool.hpp"
#include "iora/network/http_server.hpp"
#include "iora/parsers/json.hpp"
#include "iora/rpc/jsonrpc_client.hpp"
#include "iora/rpc/jsonrpc_http.hpp"
#include "iora/rpc/jsonrpc_server.hpp"

#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace std::chrono_literals;
using iora::parsers::Json;

int main()
{
  // D-LIFETIME (docs/rpc/jsonrpc.md, Component Deep Dive / Usage Guide): declare the
  // JsonRpcServer BEFORE the HttpServer. The endpoint holds RAW references to both,
  // so both must outlive it; declaring the server first makes scope-exit destruction
  // (reverse of declaration) unwind endpoint -> http -> server, the safe order.
  iora::rpc::JsonRpcServer server;
  server.registerMethod("add",
                        [](const Json &params, iora::rpc::RpcContext &)
                        {
                          return Json(params["a"].get<int>() + params["b"].get<int>());
                        });

  // A fixed loopback port for the demo; a real service chooses its own.
  // http.start() below throws if the port cannot be bound (e.g. already in use).
  const std::uint16_t port = 18080;
  iora::network::HttpServer http("127.0.0.1", static_cast<int>(port));

  iora::rpc::JsonRpcHttpOptions options;
  // Server-side negotiated gzip: decode gzip request bodies, and compress responses
  // when the client accepts gzip.
  options.enableRequestDecompression = true;
  options.enableResponseCompression = true;
  // DEMONSTRATION ONLY: threshold 0 forces gzip on every non-empty body (the
  // compress test is strictly size > threshold), so this example actually runs the
  // content-coding path. Production should keep the 1024 default (gzipping tiny
  // bodies wastes CPU and can even expand them).
  options.compressionThreshold = 0;

  // The endpoint holds raw refs to server + http; keep it in a unique_ptr so it can
  // be destroyed FIRST, before http and server, during teardown.
  auto endpoint = std::make_unique<iora::rpc::JsonRpcHttpEndpoint>(server, http, options);
  http.start();

  // The ThreadPool MUST outlive the JsonRpcClient (the client's destructor blocking-
  // drains its in-flight work onto the pool), so declare the pool first.
  iora::core::ThreadPool pool(2, 4, 2s);

  iora::rpc::Config config;
  config.requestTimeout = 5s;
  config.connectionTimeout = 2s;
  config.maxRetries = 0;
  // Client-side request compression (client -> server direction).
  config.enableRequestCompression = true;
  // DEMONSTRATION ONLY: keep the 1024 default in production (see the server note).
  config.compressionThreshold = 0;
  // config.advertiseAcceptEncoding defaults true, which is what makes the server
  // compress the response -- do NOT set it false or the response gzip half is lost.

  iora::rpc::JsonRpcClient client(pool, config);

  // The URL path must match options.path, which defaults to "/rpc" (unset above).
  const std::string url = "http://localhost:" + std::to_string(port) + "/rpc";
  Json params;
  params["a"] = 2;
  params["b"] = 3;
  // An empty header list; this is where per-call auth or custom headers would go.
  const std::vector<std::pair<std::string, std::string>> noHeaders;

  // call() throws on failure (a RemoteError JSON-RPC error, a network/transport
  // failure, or a closing client). A real caller handles these; here we report and
  // fall through to orderly teardown so the example never std::terminate()s.
  try
  {
    const Json result = client.call(url, "add", params, noHeaders);
    std::cout << "add(2, 3) = " << result.get<int>() << std::endl;
  }
  catch (const std::exception &ex)
  {
    std::cerr << "jsonrpc call failed: " << ex.what() << std::endl;
  }

  // Safe teardown (D-LIFETIME): stop the server first (it drains any in-flight
  // dispatch), then destroy the endpoint before http and server unwind at scope
  // exit. The pool, declared before the client, outlives it.
  http.stop();
  endpoint.reset();
  return 0;
}
