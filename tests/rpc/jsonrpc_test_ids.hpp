// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Lightweight shared id-extraction helpers for the iora::rpc test suite
// (Slice-B review L9 + S-4). Split out of jsonrpc_test_support.hpp so consumers
// that need ONLY the JSON-RPC id nugget (client.cpp, the 6646-line client_pool.cpp)
// do not transitively compile the server-composition fixture (JsonRpcHttpEndpoint /
// JsonRpcServer / accept-encoding / content-coding). Depends only on the JSON parser
// and gzip. jsonrpc_test_support.hpp includes this header.
#pragma once

#include "iora/parsers/json.hpp"
#include "iora/util/gzip.hpp"

#include <cstddef>
#include <string>

namespace testrpc
{

/// \brief Extract the JSON-RPC request id from \p body ({} object with an "id"),
/// or a null Json when the body is unparseable or carries no id. The migrated
/// client enforces id-correlation (task-5b.3), so a success fixture MUST echo this
/// back or the client rejects the reply.
inline iora::parsers::Json requestId(const std::string &body)
{
  const auto pr = iora::parsers::Json::parse(body, iora::parsers::ParseLimits{});
  if (pr.ok && pr.value.is_object() && pr.value.contains("id"))
  {
    return pr.value["id"];
  }
  return iora::parsers::Json(nullptr);
}

/// \brief Like requestId, but first gunzips \p body when it is gzip-encoded (the
/// raw HttpServer does not auto-decompress request bodies), for a fixture that
/// must echo the id of a client-compressed request.
inline iora::parsers::Json requestIdInflating(const std::string &body, bool gzip,
                                              std::size_t cap = 1u << 20)
{
  if (!gzip)
  {
    return requestId(body);
  }
  auto r = iora::util::Gzip::decompress(body, cap);
  return requestId(r.isOk() ? r.value() : body);
}

} // namespace testrpc
