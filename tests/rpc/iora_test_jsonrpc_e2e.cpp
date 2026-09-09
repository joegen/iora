// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// THE ACCEPTANCE TEST (tracker 2026-07-26-1 phase-8, task-8.1). Composes
// network::HttpServer + rpc::JsonRpcServer + rpc::JsonRpcHttpEndpoint +
// rpc::JsonRpcClient and performs a real round trip, a notification (204), and a
// batch — with NO IoraService. Its cleanliness IS the deliverable: it must not
// mention IoraService, loadSingleModule, callExportedApi, or a .so path.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/http_server.hpp"
#include "iora/rpc/jsonrpc_client.hpp"
#include "iora/rpc/jsonrpc_http.hpp"
#include "iora/rpc/jsonrpc_server.hpp"

#include <string>

using iora::parsers::Json;
using iora::rpc::JsonRpcClient;
using iora::rpc::JsonRpcHttpEndpoint;
using iora::rpc::JsonRpcHttpOptions;
using iora::rpc::JsonRpcServer;

TEST_CASE("scaffold placeholder — e2e composition authored in phase-8", "[jsonrpc_e2e][scaffold]")
{
  JsonRpcServer server;
  REQUIRE(server.getMethodNames().empty());
}
