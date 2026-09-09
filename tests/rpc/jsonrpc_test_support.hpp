// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Shared test-support helpers for the iora::rpc test suite (tests/rpc/).
// Introduced by the Slice-B review (tracker 2026-07-26-1):
//   * testrpc::requestId / requestIdInflating (L9) — the id-extraction nugget every
//     in-process fixture needs now that the migrated client enforces id-correlation
//     (task-5b.3). The envelope BUILDERS stay per-fixture (they legitimately differ:
//     success result vs {ok:true} vs gzip-compressed); only the extraction is shared.
//   * testrpc::ComposedRpcServer (L8) — the HttpServer + JsonRpcServer +
//     JsonRpcHttpEndpoint composition the gzip request/response suites (and task-8.1
//     e2e) each stand up. The D-LIFETIME member ordering (JsonRpcServer before
//     HttpServer, endpoint last, stop() in dtor — task-3.3) is a correctness
//     precondition, encoded ONCE here instead of hand-replicated per fixture.
#pragma once

#include "iora/rpc/jsonrpc_http.hpp"
#include "iora/rpc/jsonrpc_server.hpp"

#include "iora/network/http_server.hpp"
#include "iora/parsers/json.hpp"

#include "iora_test_net_utils.hpp" // testnet::getFreePortTCP
#include "jsonrpc_test_ids.hpp"    // testrpc::requestId / requestIdInflating (S-4 light header)

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace testrpc
{

/// \brief Options for ComposedRpcServer. Defaults match JsonRpcHttpOptions'
/// negotiated-gzip defaults; `registerMethods` defaults to a single `echo` method
/// that returns its params.
struct ComposedRpcServerOptions
{
  bool enableRequestDecompression = false;
  bool enableResponseCompression = false;
  std::size_t compressionThreshold = 1024;
  bool requireAuth = false; // requireAuth && no tokenValidator FAILS CLOSED (401)
  std::function<void(iora::rpc::JsonRpcServer &)> registerMethods;
};

/// \brief A real wire-level JSON-RPC server: HttpServer + JsonRpcServer +
/// JsonRpcHttpEndpoint on an ephemeral loopback port. Member order pins the
/// D-LIFETIME precondition (task-3.3): _server outlives _http's stop()/destroy, and
/// _endpoint (which references both) is destroyed first.
class ComposedRpcServer
{
public:
  explicit ComposedRpcServer(ComposedRpcServerOptions opts = {})
      : _port(testnet::getFreePortTCP()), _http("127.0.0.1", static_cast<int>(_port))
  {
    if (opts.registerMethods)
    {
      opts.registerMethods(_server);
    }
    else
    {
      _server.registerMethod("echo",
                             [](const iora::parsers::Json &p, iora::rpc::RpcContext &) { return p; });
    }
    iora::rpc::JsonRpcHttpOptions ho;
    ho.enableRequestDecompression = opts.enableRequestDecompression;
    ho.enableResponseCompression = opts.enableResponseCompression;
    ho.compressionThreshold = opts.compressionThreshold;
    ho.requireAuth = opts.requireAuth;
    _endpoint = std::make_unique<iora::rpc::JsonRpcHttpEndpoint>(_server, _http, ho);
    _http.start();
    // Slice-B review T-1: HttpServer::start() binds the listen socket synchronously
    // (a later connect is backlog-queued even before the accept thread spins up), so a
    // bounded connect-poll confirms readiness with near-zero delay rather than a fixed,
    // and weaker, 200 ms sleep.
    waitListening_(_port);
  }
  ~ComposedRpcServer() { _http.stop(); }

  ComposedRpcServer(const ComposedRpcServer &) = delete;
  ComposedRpcServer &operator=(const ComposedRpcServer &) = delete;
  // Effectively non-movable already (user dtor + deleted copy), but state it
  // explicitly so the invariant is regression-proof (Slice-B review C-2), matching
  // JsonRpcHttpEndpoint's own non-movable intent.
  ComposedRpcServer(ComposedRpcServer &&) = delete;
  ComposedRpcServer &operator=(ComposedRpcServer &&) = delete;

  std::uint16_t port() const { return _port; }
  std::string url() const { return "http://localhost:" + std::to_string(_port) + "/rpc"; }

private:
  /// \brief Block until a loopback TCP connect to \p port succeeds, or \p bound
  /// elapses (bounded so a wedged listener fails the test rather than hangs).
  static void waitListening_(std::uint16_t port,
                             std::chrono::milliseconds bound = std::chrono::seconds(2))
  {
    const auto deadline = std::chrono::steady_clock::now() + bound;
    for (;;)
    {
      int fd = ::socket(AF_INET, SOCK_STREAM, 0);
      if (fd >= 0)
      {
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        a.sin_addr.s_addr = ::inet_addr("127.0.0.1");
        const bool ok = ::connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0;
        ::close(fd);
        if (ok)
        {
          return;
        }
      }
      if (std::chrono::steady_clock::now() >= deadline)
      {
        return; // give up; a subsequent client call surfaces the failure loudly
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
  }

  std::uint16_t _port;
  iora::rpc::JsonRpcServer _server;
  iora::network::HttpServer _http;
  std::unique_ptr<iora::rpc::JsonRpcHttpEndpoint> _endpoint;
};

} // namespace testrpc
