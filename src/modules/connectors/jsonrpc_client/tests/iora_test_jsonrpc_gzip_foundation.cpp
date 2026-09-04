// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Foundation tests for the JSON-RPC bidirectional negotiated-gzip Consumer C
// (tracker 2026-09-04-2, arch architecture/iora/jsonrpc_gzip_compression.json).
// Covers the foundation slice ONLY: the shared types, the client + server config
// surface + its test seam, and the two cross-cutting prerequisite seams
// (isListValuedHeader combine + the promoted iora::parsers::gzipAcceptable helper).
// Request/response behavior lands in the phase-2/phase-3 trackers.

#include "../jsonrpc_client.hpp" // Config, ContentCodingRejectedError, OriginRequestCompressionState

#include "iora/iora.hpp"
#include "iora/network/http_client.hpp"  // HttpClient::isRequestProvablyNotSent, HttpRequestNotSentError
#include "iora/parsers/accept_encoding.hpp" // promoted gzipAcceptable
#include "iora/parsers/http_message.hpp"    // isListValuedHeader, addOrCombineHeader, HttpRequest

#include <catch2/catch.hpp>

#include <chrono>
#include <filesystem>
#include <optional>
#include <string>

using namespace iora::modules::connectors;

// ─────────────────────────────────────────────────────────────────────────────
// (a) ContentCodingRejectedError catch-shape (task-1.1)
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("gzip foundation: ContentCodingRejectedError catch-shape", "[gzip-foundation][types]")
{
  ContentCodingRejectedError e("http://host:8080", "server rejected content-coding (415)");

  SECTION("carries the origin and message")
  {
    REQUIRE(e.origin() == "http://host:8080");
    REQUIRE(std::string(e.what()) == "server rejected content-coding (415)");
  }

  SECTION("is catchable as std::exception")
  {
    bool caught = false;
    try
    {
      throw ContentCodingRejectedError("o", "boom");
    }
    catch (const std::exception &ex)
    {
      caught = true;
      REQUIRE(std::string(ex.what()) == "boom");
    }
    REQUIRE(caught);
  }

  SECTION("isRequestProvablyNotSent returns false (a 415 is a completed round-trip)")
  {
    // The not-sent retry gate must NOT swallow it: it is not an
    // HttpRequestNotSentError, so the gate falls through to the bare rethrow that
    // reaches the compression wrapper. The cross-hierarchy dynamic_casts are
    // routed through a std::exception& base pointer (exactly as
    // isRequestProvablyNotSent does) so they are genuine RUNTIME checks — a direct
    // cast from ContentCodingRejectedError* is a compile-time "can never succeed".
    const std::exception &base = e;
    REQUIRE_FALSE(iora::network::HttpClient::isRequestProvablyNotSent(e));
    REQUIRE(dynamic_cast<const iora::network::HttpRequestNotSentError *>(&base) == nullptr);
    // Mutation guard: a genuine HttpRequestNotSentError DOES resolve through the
    // same base pointer, so the negative check above is non-vacuous.
    iora::network::HttpRequestNotSentError notSent("x");
    const std::exception &notSentBase = notSent;
    REQUIRE(dynamic_cast<const iora::network::HttpRequestNotSentError *>(&notSentBase) != nullptr);
    REQUIRE(iora::network::HttpClient::isRequestProvablyNotSent(notSent));
  }

  SECTION("is NOT a JsonRpcError (a generic JsonRpcError catcher must not intercept it)")
  {
    const std::exception &base = e;
    REQUIRE(dynamic_cast<const JsonRpcError *>(&base) == nullptr);
    // Mutation guard: a genuine JsonRpcError DOES resolve through the same base
    // pointer, so the check above is non-vacuous.
    JsonRpcError je("x");
    const std::exception &jeBase = je;
    REQUIRE(dynamic_cast<const JsonRpcError *>(&jeBase) != nullptr);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) OriginRequestCompressionState defaults + constexpr TTL (task-1.2)
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("gzip foundation: OriginRequestCompressionState defaults + TTL",
          "[gzip-foundation][types]")
{
  OriginRequestCompressionState s;

  SECTION("default field values")
  {
    REQUIRE_FALSE(s.configuredRequestCapable);
    REQUIRE_FALSE(s.latchedOff);
    REQUIRE(s.ttlExpiry == std::chrono::steady_clock::time_point{});
    REQUIRE_FALSE(s.seededServerAcceptsGzip.has_value());
  }

  SECTION("kRequestCompressionTtl is a compile-time 300s DURATION, not the time_point field")
  {
    static_assert(OriginRequestCompressionState::kRequestCompressionTtl ==
                    std::chrono::seconds(300),
                  "re-probe interval must be 300 seconds");
    REQUIRE(OriginRequestCompressionState::kRequestCompressionTtl.count() == 300);
    // It is a std::chrono::seconds duration — distinct type from ttlExpiry
    // (a steady_clock::time_point). Confirm they are not the same field/type.
    static_assert(!std::is_same<decltype(OriginRequestCompressionState::kRequestCompressionTtl),
                                decltype(s.ttlExpiry)>::value,
                  "TTL constant must be a duration, not a time_point");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// (c-client) JsonRpcClient::Config compression defaults (task-2.1)
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("gzip foundation: client Config compression defaults", "[gzip-foundation][config]")
{
  Config cfg;
  REQUIRE_FALSE(cfg.enableRequestCompression);
  REQUIRE(cfg.advertiseAcceptEncoding);
  REQUIRE(cfg.compressionThreshold == std::size_t{1024});
  REQUIRE(cfg.maxDecodedResponseBytes == std::size_t{16} * 1024 * 1024);
}

// ─────────────────────────────────────────────────────────────────────────────
// (c-server) mod_jsonrpc_server config defaults via the getConfig test seam
//            (task-2.2). Loads the real server .so and reads back its effective
//            config — the .so-boundary equivalent of "public const getters".
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("gzip foundation: server config defaults via getConfig seam",
          "[gzip-foundation][config][plugin]")
{
  iora::IoraService::Config svcConfig;
  svcConfig.server.port = 8138;
  svcConfig.log.level = "info";

  iora::IoraService::shutdown(); // ensure clean state
  iora::IoraService::init(svcConfig);
  iora::IoraService &svc = iora::IoraService::instanceRef();
  iora::IoraService::AutoServiceShutdown autoShutdown(svc);

  auto serverPluginPath = iora::util::resolveRelativePath(
                            iora::util::getExecutableDir(),
                            "../../../endpoints/jsonrpc_server/") +
                          "/mod_jsonrpc_server.so";
  REQUIRE(std::filesystem::exists(serverPluginPath));
  REQUIRE(svc.loadSingleModule(serverPluginPath));

  auto cfg = svc.callExportedApi<iora::parsers::Json>("jsonrpc.getConfig");

  // Negotiated-gzip server defaults (arch configSurface.serverFields).
  REQUIRE(cfg["enableRequestDecompression"].get<bool>() == false);
  REQUIRE(cfg["enableResponseCompression"].get<bool>() == false);
  REQUIRE(cfg["compressionThreshold"].get<std::size_t>() == std::size_t{1024});
  // The request cap the decode path reuses is the existing _maxRequestBytes
  // (arch caps.server: one constant is BOTH the compressed-input pre-filter and
  // the decoded maxOutputBytes cap). Default 1 MiB.
  REQUIRE(cfg["maxRequestBytes"].get<std::size_t>() == std::size_t{1} * 1024 * 1024);
}

// ─────────────────────────────────────────────────────────────────────────────
// (d) isListValuedHeader COMBINE for Content-Encoding + Accept-Encoding (task-3.1)
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("gzip foundation: isListValuedHeader predicate", "[gzip-foundation][combine]")
{
  using iora::network::detail::isListValuedHeader;

  // Newly list-valued (Consumer C).
  REQUIRE(isListValuedHeader("Content-Encoding"));
  REQUIRE(isListValuedHeader("Accept-Encoding"));
  // Case-insensitive name match.
  REQUIRE(isListValuedHeader("content-encoding"));
  REQUIRE(isListValuedHeader("accept-encoding"));
  // Pre-existing list-valued set unchanged.
  REQUIRE(isListValuedHeader("X-Forwarded-For"));
  REQUIRE(isListValuedHeader("Forwarded"));
  REQUIRE(isListValuedHeader("Via"));
  // Non-list headers that carry intrinsic commas remain last-wins (must NOT combine).
  REQUIRE_FALSE(isListValuedHeader("Content-Type"));
  REQUIRE_FALSE(isListValuedHeader("Set-Cookie"));
  REQUIRE_FALSE(isListValuedHeader("Retry-After"));
  REQUIRE_FALSE(isListValuedHeader("WWW-Authenticate"));
}

TEST_CASE("gzip foundation: addOrCombineHeader combines Content/Accept-Encoding in order",
          "[gzip-foundation][combine]")
{
  using iora::network::HttpHeaders;
  using iora::network::detail::addOrCombineHeader;

  SECTION("Content-Encoding combines in arrival order, not reordered")
  {
    HttpHeaders h;
    addOrCombineHeader(h, "Content-Encoding", "gzip");
    addOrCombineHeader(h, "Content-Encoding", "identity");
    REQUIRE(h.at("Content-Encoding") == "gzip, identity");
  }

  SECTION("Accept-Encoding combines in arrival order")
  {
    HttpHeaders h;
    addOrCombineHeader(h, "Accept-Encoding", "gzip");
    addOrCombineHeader(h, "Accept-Encoding", "identity;q=0");
    REQUIRE(h.at("Accept-Encoding") == "gzip, identity;q=0");
  }

  SECTION("whitespace-only (empty after trim) list element is skipped")
  {
    HttpHeaders h;
    addOrCombineHeader(h, "Content-Encoding", "gzip");
    addOrCombineHeader(h, "Content-Encoding", ""); // pre-trimmed empty element
    REQUIRE(h.at("Content-Encoding") == "gzip");
  }

  SECTION("non-list header stays last-wins")
  {
    HttpHeaders h;
    addOrCombineHeader(h, "Content-Type", "text/plain");
    addOrCombineHeader(h, "Content-Type", "application/json");
    REQUIRE(h.at("Content-Type") == "application/json");
  }
}

TEST_CASE("gzip foundation: real ingress path combines duplicate encodings",
          "[gzip-foundation][combine]")
{
  using iora::network::HttpRequest;

  SECTION("duplicate Content-Encoding field-lines combine, case-insensitive name")
  {
    const std::string wire = "POST /rpc HTTP/1.1\r\n"
                             "Host: h\r\n"
                             "Content-Encoding: gzip\r\n"
                             "content-encoding: identity\r\n"
                             "\r\n";
    HttpRequest req = HttpRequest::fromWireFormat(wire);
    REQUIRE(req.headers.at("Content-Encoding") == "gzip, identity");
  }

  SECTION("duplicate Accept-Encoding field-lines combine")
  {
    const std::string wire = "POST /rpc HTTP/1.1\r\n"
                             "Host: h\r\n"
                             "Accept-Encoding: gzip\r\n"
                             "Accept-Encoding: identity;q=0\r\n"
                             "\r\n";
    HttpRequest req = HttpRequest::fromWireFormat(wire);
    REQUIRE(req.headers.at("Accept-Encoding") == "gzip, identity;q=0");
  }

  SECTION("whitespace-only Content-Encoding field-line is skipped end-to-end (§5.6.1)")
  {
    // parseHeaderLine OWS-trims the second value to "" and addOrCombineHeader skips
    // the empty list element — exercised here through the REAL ingress path for
    // Content-Encoding (not just the addOrCombineHeader unit), closing the CR-1/WEB-1
    // finding that the §5.6.1 skip was only unit-tested for CE.
    const std::string wire = "POST /rpc HTTP/1.1\r\n"
                             "Host: h\r\n"
                             "Content-Encoding: gzip\r\n"
                             "Content-Encoding:    \r\n"
                             "\r\n";
    HttpRequest req = HttpRequest::fromWireFormat(wire);
    REQUIRE(req.headers.at("Content-Encoding") == "gzip");
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// (e) promoted gzipAcceptable q-value matrix incl. §12.5.3 precedence (task-3.2)
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("gzip foundation: promoted gzipAcceptable q-value matrix", "[gzip-foundation][qvalue]")
{
  using iora::parsers::gzipAcceptable;

  // Plain acceptance.
  REQUIRE(gzipAcceptable("gzip"));
  REQUIRE(gzipAcceptable("gzip;q=1"));
  REQUIRE(gzipAcceptable("gzip;q=0.5"));
  REQUIRE(gzipAcceptable("identity, gzip"));

  // gzip;q=0 alone -> not acceptable.
  REQUIRE_FALSE(gzipAcceptable("gzip;q=0"));

  // Explicit gzip q=0 beats a '*' fallback (RFC 9110 §12.5.3 precedence).
  REQUIRE_FALSE(gzipAcceptable("gzip;q=0, *"));
  REQUIRE_FALSE(gzipAcceptable("*, gzip;q=0"));

  // '*' fallback applies only when gzip is not explicitly listed.
  REQUIRE(gzipAcceptable("*"));
  REQUIRE(gzipAcceptable("*;q=1"));
  REQUIRE_FALSE(gzipAcceptable("*;q=0"));
  REQUIRE_FALSE(gzipAcceptable("identity")); // only identity -> gzip not acceptable

  // Absent / empty header -> identity (NOT acceptable).
  REQUIRE_FALSE(gzipAcceptable(""));
  REQUIRE_FALSE(gzipAcceptable("   "));

  // Case-insensitive coding token.
  REQUIRE(gzipAcceptable("GZIP"));
  REQUIRE(gzipAcceptable("GzIp;q=0.1"));

  // Malformed q -> 0.0 (conservative, not acceptable).
  REQUIRE_FALSE(gzipAcceptable("gzip;q=bad"));
  REQUIRE_FALSE(gzipAcceptable("gzip;q=1.5")); // out of range
  REQUIRE_FALSE(gzipAcceptable("gzip;q=2"));
}

// ─────────────────────────────────────────────────────────────────────────────
// (f) composed combine -> gzipAcceptable pipeline (W-M1 seam, task-4.2(f))
// ─────────────────────────────────────────────────────────────────────────────
TEST_CASE("gzip foundation: combined Accept-Encoding negotiates gzip (W-M1 seam)",
          "[gzip-foundation][composed]")
{
  using iora::network::HttpHeaders;
  using iora::network::detail::addOrCombineHeader;
  using iora::parsers::gzipAcceptable;

  // A split Accept-Encoding ('gzip' on one line, 'identity;q=0' on another) must
  // combine to "gzip, identity;q=0" and still negotiate gzip (gzip defaults q=1).
  // This locks the combine -> negotiate seam that the phase-3 server response
  // path depends on; a last-wins collapse would have dropped 'gzip'.
  HttpHeaders h;
  addOrCombineHeader(h, "Accept-Encoding", "gzip");
  addOrCombineHeader(h, "Accept-Encoding", "identity;q=0");
  REQUIRE(h.at("Accept-Encoding") == "gzip, identity;q=0");
  REQUIRE(gzipAcceptable(h.at("Accept-Encoding")));

  // Mutation guard: had the collapse kept only "identity;q=0", gzip would be
  // rejected — confirm that string genuinely resolves to not-acceptable.
  REQUIRE_FALSE(gzipAcceptable("identity;q=0"));
}
