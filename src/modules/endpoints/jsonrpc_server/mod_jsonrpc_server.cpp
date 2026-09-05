// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#include "jsonrpc_server.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "iora/iora.hpp"
#include "iora/core/string_utils.hpp"    // StringUtils::iequals/trim (content-coding parse)
#include "iora/parsers/accept_encoding.hpp" // gzipAcceptable (Consumer C, phase 3 response)
#include "iora/parsers/content_coding.hpp"  // splitContentCodings (Consumer C, phase 2/3)
#include "iora/util/gzip.hpp"            // request-body gzip decode (Consumer C, phase 2)

namespace iora
{

/// \brief JSON-RPC 2.0 endpoint as an IoraService::Plugin.
///
/// Exposes POST {path} on the service webhookServer and exports the following API
/// callables via IoraService::exportApi:
///   - "jsonrpc.version"       -> std::uint32_t()
///   - "jsonrpc.register"      -> void(const std::string&, std::function<iora::parsers::Json(const
///   iora::parsers::Json&)>)
///   - "jsonrpc.registerWithOptions" -> void(const std::string&,
///   std::function<iora::parsers::Json(const iora::parsers::Json&)>, const iora::parsers::Json&)
///   - "jsonrpc.unregister"    -> bool(const std::string&)
///   - "jsonrpc.has"           -> bool(const std::string&)
///   - "jsonrpc.getMethods"    -> std::vector<std::string>()
///   - "jsonrpc.getStats"      -> iora::parsers::Json()
///   - "jsonrpc.resetStats"    -> void()
class JsonRpcServerPlugin : public IoraService::Plugin
{
public:
  JsonRpcServerPlugin(iora::IoraService *service)
      : Plugin(service), _enabled(true), _path("/rpc"), _maxRequestBytes(1 * 1024 * 1024),
        _maxBatchItems(50), _requireAuth(false), _timeoutMs(5000), _logRequests(false),
        _enableMetrics(true), _enableRequestDecompression(false),
        _enableResponseCompression(false), _compressionThreshold(1024)
  {
  }

  const char *name() const { return "jsonrpc"; }

  void onLoad(IoraService *service) override
  {
    // Load configuration from IoraService config system
    auto *loader = service->configLoader().get();
    if (loader)
    {
      try
      {
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.enabled"))
          _enabled = *v;
        if (auto v = loader->getString("iora.modules.jsonrpc_server.path"))
          _path = *v;
        if (auto v = loader->getInt("iora.modules.jsonrpc_server.maxRequestBytes"))
          _maxRequestBytes = static_cast<std::size_t>(*v);
        if (auto v = loader->getInt("iora.modules.jsonrpc_server.maxBatchItems"))
          _maxBatchItems = static_cast<std::size_t>(*v);
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.requireAuth"))
          _requireAuth = *v;
        if (auto v = loader->getInt("iora.modules.jsonrpc_server.timeoutMs"))
          _timeoutMs = *v;
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.logRequests"))
          _logRequests = *v;
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.enableMetrics"))
          _enableMetrics = *v;
        // Negotiated gzip compression (Consumer C). enableRequestDecompression
        // gates only DECODING — the request Content-Encoding is examined
        // regardless (phase 2). The behavior these drive lands in phase 2; the
        // fields + their config keys are established here at foundation stage.
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.enableRequestDecompression"))
          _enableRequestDecompression = *v;
        if (auto v = loader->getBool("iora.modules.jsonrpc_server.enableResponseCompression"))
          _enableResponseCompression = *v;
        if (auto v = loader->getInt("iora.modules.jsonrpc_server.compressionThreshold"))
          _compressionThreshold = static_cast<std::size_t>(*v);

        iora::core::Logger::info("JSON-RPC server plugin configured: path=" + _path +
                                 ", auth=" + (_requireAuth ? "true" : "false") +
                                 ", timeout=" + std::to_string(_timeoutMs) + "ms");
      }
      catch (const std::exception &e)
      {
        iora::core::Logger::warning(
          "Failed to load JSON-RPC configuration: " + std::string(e.what()) + ", using defaults");
      }
    }

    // Export callable APIs (matches IoraService::exportApi signature).
    service->exportApi(*this, "jsonrpc.version",
                       [this]() -> std::uint32_t
                       {
                         return 2U; // Version 2 with enhanced features
                       });

    service->exportApi(
      *this, "jsonrpc.register",
      [this](const std::string &method,
             std::function<iora::parsers::Json(const iora::parsers::Json &)> handler) -> void
      {
        _router.registerMethod(method,
                               [handler](const iora::parsers::Json &params,
                                         modules::jsonrpc::RpcContext &ctx) -> iora::parsers::Json
                               { return handler(params); });
      });

    service->exportApi(
      *this, "jsonrpc.registerWithOptions",
      [this](const std::string &method,
             std::function<iora::parsers::Json(const iora::parsers::Json &)> handler,
             const iora::parsers::Json &optionsJson) -> void
      {
        modules::jsonrpc::MethodOptions options;
        if (optionsJson.contains("requireAuth") && optionsJson["requireAuth"].is_boolean())
          options.requireAuth = optionsJson["requireAuth"];
        if (optionsJson.contains("timeout") && optionsJson["timeout"].is_number_integer())
          options.timeout = std::chrono::milliseconds(optionsJson["timeout"].get<int>());
        if (optionsJson.contains("maxRequestSize") &&
            optionsJson["maxRequestSize"].is_number_integer())
          options.maxRequestSize = optionsJson["maxRequestSize"].get<std::size_t>();

        _router.registerMethod(
          method,
          [handler](const iora::parsers::Json &params,
                    modules::jsonrpc::RpcContext &ctx) -> iora::parsers::Json
          { return handler(params); },
          options);
      });

    service->exportApi(*this, "jsonrpc.unregister", [this](const std::string &method) -> bool
                       { return _router.unregisterMethod(method); });

    service->exportApi(*this, "jsonrpc.has", [this](const std::string &method) -> bool
                       { return _router.hasMethod(method); });

    service->exportApi(*this, "jsonrpc.getMethods",
                       [this]() -> std::vector<std::string> { return _router.getMethodNames(); });

    service->exportApi(*this, "jsonrpc.getStats",
                       [this]() -> iora::parsers::Json
                       {
                         const auto &stats = _router.getStats();
                         auto statsJson = iora::parsers::Json::object();
                         statsJson["totalRequests"] = stats.totalRequests.load();
                         statsJson["successfulRequests"] = stats.successfulRequests.load();
                         statsJson["failedRequests"] = stats.failedRequests.load();
                         statsJson["timeoutRequests"] = stats.timeoutRequests.load();
                         statsJson["batchRequests"] = stats.batchRequests.load();
                         statsJson["notificationRequests"] = stats.notificationRequests.load();
                         return statsJson;
                       });

    service->exportApi(*this, "jsonrpc.resetStats", [this]() -> void { _router.resetStats(); });

    // Config-introspection seam. The plugin class is compiled only into the .so
    // (never header-visible), so a friend test-access struct or public getters —
    // the two seams the client uses — are unreachable across the .so boundary. An
    // exported readback is the .so-boundary equivalent of "public const getters"
    // (mirroring jsonrpc.getStats) and lets a test assert the effective config,
    // including the negotiated-gzip defaults, after loadSingleModule -> onLoad.
    service->exportApi(*this, "jsonrpc.getConfig",
                       [this]() -> iora::parsers::Json
                       {
                         auto cfg = iora::parsers::Json::object();
                         cfg["path"] = _path;
                         cfg["maxRequestBytes"] = _maxRequestBytes;
                         cfg["maxBatchItems"] = _maxBatchItems;
                         cfg["requireAuth"] = _requireAuth;
                         cfg["timeoutMs"] = _timeoutMs;
                         cfg["enableMetrics"] = _enableMetrics;
                         cfg["enableRequestDecompression"] = _enableRequestDecompression;
                         cfg["enableResponseCompression"] = _enableResponseCompression;
                         cfg["compressionThreshold"] = _compressionThreshold;
                         return cfg;
                       });

    // Mount POST {path} directly on the webhookServer.
    service->webhookServer()->onPost(_path, [this](const iora::network::WebhookServer::Request &req,
                                                   iora::network::WebhookServer::Response &res)
                                     { this->handlePost(req, res); });
  }

private:
  /// \brief Emit a JSON-RPC 2.0 error envelope on \p res with the given HTTP
  /// \p status and JSON-RPC \p code/\p message. DRYs handlePost's error sites so
  /// the envelope shape cannot drift between them (simplification L5).
  /// CONTRACT: \p message MUST be a trusted, JSON-safe literal (no '"' or '\\' or
  /// control octets) — it is interpolated verbatim, NOT escaped. Every caller here
  /// passes a compile-time literal. If an untrusted/dynamic string is ever emitted,
  /// escape it first (do NOT pass it through this helper raw).
  static void setJsonRpcError_(iora::network::WebhookServer::Response &res, int status, int code,
                               const std::string &message)
  {
    res.status = status;
    // DP-9 invariant, enforced defensively (not merely by statement order): every
    // non-2xx error body stays identity. If a throw during response compression
    // unwinds into handlePost's catch AFTER Vary / Content-Encoding were set on the
    // 200 path, those negotiation headers would otherwise leak onto the 500 (and a
    // stray Content-Encoding: gzip on an identity body would make a client try to
    // inflate plaintext). Erase them here so the invariant holds under exception
    // unwind regardless of where the throw originated.
    res.headers.erase("Content-Encoding");
    res.headers.erase("Vary");
    res.set_content("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":" + std::to_string(code) +
                      ",\"message\":\"" + message + "\"},\"id\":null}",
                    "application/json");
  }

  void handlePost(const iora::network::WebhookServer::Request &req,
                  iora::network::WebhookServer::Response &res)
  {

    auto startTime = std::chrono::steady_clock::now();

    if (_logRequests)
    {
      iora::core::Logger::debug("JSON-RPC request: " + std::to_string(req.body.size()) + " bytes");
    }

    // Set CORS headers if needed
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
    // Consumer C DP-10 / task-1.5: allow a cross-origin fetch to manually set
    // Content-Encoding (it is NOT a Fetch forbidden request-header, so a browser
    // CAN drive request compression by gzipping the body itself). Do NOT add
    // Accept-Encoding — it IS a Fetch forbidden request-header a browser cannot set.
    res.set_header("Access-Control-Allow-Headers",
                   "Content-Type, Authorization, Content-Encoding");

    // Handle preflight OPTIONS request
    if (req.method == iora::network::HttpMethod::OPTIONS)
    {
      res.status = 200;
      return;
    }

    // Enforce JSON content type for JSON-RPC 2.0.
    {
      auto it = req.headers.find("Content-Type");
      if (it == req.headers.end() || it->second.find("application/json") == std::string::npos)
      {
        // Media-type 415 — deliberately carries NO Accept-Encoding (that header
        // belongs only to the content-coding 415 below, DP-7 disambiguation).
        setJsonRpcError_(res, 415, -32600, "Unsupported Media Type");

        if (_logRequests)
        {
          iora::core::Logger::warning("JSON-RPC request rejected: unsupported media type");
        }
        return;
      }
    }

    // Logical size guard (webhookServer also caps internally).
    if (req.body.size() > _maxRequestBytes)
    {
      setJsonRpcError_(res, 413, -32600, "Request Entity Too Large");

      if (_logRequests)
      {
        iora::core::Logger::warning("JSON-RPC request rejected: body size " +
                                    std::to_string(req.body.size()) + " exceeds limit " +
                                    std::to_string(_maxRequestBytes));
      }
      return;
    }

    // Optional auth integration
    std::optional<std::string> subject;
    if (_requireAuth)
    {
      // Extract authorization from header (basic implementation)
      auto authHeader = req.headers.find("Authorization");
      if (authHeader != req.headers.end())
      {
        std::string auth = authHeader->second;
        if (auth.size() > 7 && auth.substr(0, 7) == "Bearer ")
        {
          // TODO: Integrate with actual auth system
          subject = auth.substr(7); // Remove "Bearer " prefix
        }
      }

      if (!subject)
      {
        setJsonRpcError_(res, 401, -32001, "Authentication required");

        if (_logRequests)
        {
          iora::core::Logger::warning("JSON-RPC request rejected: authentication required");
        }
        return;
      }
    }

    // ── Consumer C phase 2: request Content-Encoding handling (DP-6/DP-7, tasks
    // 1.1-1.4). Runs AFTER auth (task-1.4): an unauthenticated caller must not be
    // able to force even incrementally-bounded decompression CPU (DoS hardening),
    // so a bad coding behind a 401 yields 401, never 415/413. The request
    // Content-Encoding is EXAMINED whenever the request reaches body handling,
    // INDEPENDENT of _enableRequestDecompression (which gates only whether gzip is
    // DECODED). The field was already combined into an ordered comma-list on
    // ingress (foundation isListValuedHeader gate). Pinned step order:
    // media-type-415 -> size-413 -> auth-401 -> HERE -> route.
    // The body handed to the router: `req.body` on the common (no-coding / identity)
    // path with NO copy; a locally-owned inflated buffer only when we actually
    // decode gzip (simplification M2 — the router takes it by const ref).
    const std::string *bodyForRouter = &req.body;
    std::string decoded; // filled only on the inflate path
    {
      const auto ceIt = req.headers.find("Content-Encoding");
      if (ceIt != req.headers.end())
      {
        const std::vector<std::string> codings = iora::parsers::splitContentCodings(ceIt->second);
        if (!codings.empty())
        {
          // Whether every coding in the list is one we can strip. gzip/x-gzip is
          // decodable ONLY when _enableRequestDecompression; identity always is.
          // The <=2 hard cap is on the TOTAL list length (INTENTIONAL, not just the
          // gzip-layer count): it bounds the O(N) CPU of a stacked-inflate chain AND
          // conservatively rejects an 'identity,identity,...,gzip' padding attack
          // that would otherwise smuggle an over-long list past a gzip-only counter.
          // An over-cap list is a distinct 'undecodable' outcome (DP-6) -> 415, never
          // a 500 and never an unbounded inflate.
          bool hasGzip = false;
          bool decodable = codings.size() <= 2;
          if (decodable)
          {
            for (const auto &c : codings)
            {
              if (iora::core::StringUtils::iequals(c, "identity"))
              {
                continue; // no-op coding
              }
              // gzip / its legacy alias x-gzip (RFC 9110 §8.4.1) — shared classifier.
              if (iora::parsers::isGzipContentCoding(c))
              {
                hasGzip = true;
                continue;
              }
              decodable = false; // unknown coding
              break;
            }
          }

          // 415 WITH Accept-Encoding listing the decodable set (identity always;
          // gzip iff enabled) whenever the request is UNDECODABLE (DP-7) — this is
          // what makes the client's latch-off fire instead of a silent 200 +
          // parse-error. The media-type 415 above deliberately carries NO
          // Accept-Encoding.
          if (!decodable || (hasGzip && !_enableRequestDecompression))
          {
            res.set_header("Accept-Encoding",
                           _enableRequestDecompression ? "gzip, identity" : "identity");
            setJsonRpcError_(res, 415, -32600, "Unsupported Content-Encoding");
            if (_logRequests)
            {
              // ceIt->second is UNTRUSTED (client-controlled); scrub before logging
              // so a hostile Content-Encoding cannot forge log lines (web W-1).
              iora::core::Logger::warning("JSON-RPC request rejected: undecodable Content-Encoding '" +
                                          iora::parsers::sanitizeCodingForLog(ceIt->second) + "'");
            }
            return;
          }

          if (hasGzip)
          {
            // Decode OUTERMOST-FIRST (reverse of the applied order). Each inflate is
            // bounded to _maxRequestBytes — the decoded ceiling, identical to the
            // identity path (gzip does NOT raise it, arch caps.server).
            // MALFORMED_INPUT -> 400, OUTPUT_TOO_LARGE -> 413.
            decoded = req.body; // the one working buffer, allocated only here
            for (auto rit = codings.rbegin(); rit != codings.rend(); ++rit)
            {
              if (iora::core::StringUtils::iequals(*rit, "identity"))
              {
                continue; // no-op
              }
              auto r = iora::util::Gzip::decompress(decoded, _maxRequestBytes);
              if (!r.isOk())
              {
                if (r.error() == iora::util::Gzip::DecompressError::OUTPUT_TOO_LARGE)
                {
                  setJsonRpcError_(res, 413, -32600, "Request Entity Too Large");
                }
                else
                {
                  setJsonRpcError_(res, 400, -32600, "Malformed Content-Encoding");
                }
                return;
              }
              decoded = std::move(r).value();
            }
            bodyForRouter = &decoded;
          }
          // All-identity (or absent gzip) falls through routing req.body directly.
        }
      }
    }

    modules::jsonrpc::RpcContext ctx{IoraService::instanceRef(), subject};

    // Set client metadata
    ctx.metadata().clientId = "unknown"; // TODO: Add remote address to WebhookServer::Request

    try
    {
      std::string out = _router.handleRequest(*bodyForRouter, ctx, _maxBatchItems);

      auto endTime = std::chrono::steady_clock::now();
      auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

      if (out.empty())
      {
        // Notification-only request or batch with only notifications.
        // CR-6 (RFC 9110 §15.3.5 / RFC 9112 §6.3): a 204 MUST carry no content.
        // HttpServer pre-populates every matched Response with
        // set_content("Not Found","text/plain") before dispatch
        // (http_server.hpp:1096-1098), so a handler that only sets status=204 would
        // emit a 204 carrying "Not Found" with Content-Length: 9. Clear the body
        // and erase the framing/type headers, mirroring HttpServer's own
        // AUTO_OPTIONS 204 handling. W-H1 widens the set of requests reaching this
        // path (failed notifications now route here too), so this clear is landed
        // alongside W-H1 rather than left to the migration's endpoint extraction.
        res.status = 204;
        res.body.clear();
        res.headers.erase("Content-Length");
        res.headers.erase("Content-Type");

        if (_logRequests)
        {
          iora::core::Logger::debug("JSON-RPC notification processed in " +
                                    std::to_string(duration.count()) + "ms");
        }
        return;
      }

      res.status = 200;
      const std::size_t responseSize = out.size(); // captured before any std::move(out) below

      // ── Consumer C phase 3: response Content-Encoding negotiation (DP-9, tasks
      // 1.1-1.3). `out` is non-empty here (the empty/notification case returned 204
      // above), so the 204/empty path never carries Content-Encoding. All non-2xx
      // error bodies exit via setJsonRpcError_ (which never touches these headers),
      // so they stay identity, including the 401.
      if (_enableResponseCompression)
      {
        // A content-negotiated 200 varies its representation by Accept-Encoding, so
        // advertise Vary on EVERY negotiated 200 — the compressed, the identity-
        // negotiated (gzip;q=0), and the no-Accept-Encoding one — for cache
        // correctness (RFC 9110 §12.5.5). When response compression is disabled no
        // negotiation occurs, so Vary is intentionally not emitted (task-1.3).
        res.set_header("Vary", "Accept-Encoding");

        // Negotiate gzip only when the client accepts it with a non-zero q (the
        // promoted RFC 9110 §12.5.3 gzipAcceptable parser: gzip;q=0 -> not
        // acceptable, '*' fallback), the body is over threshold, and non-empty. The
        // request Accept-Encoding was already combined into one ordered comma-list on
        // ingress (foundation isListValuedHeader gate), so a split field is handled.
        // An unsatisfiable Accept-Encoding (e.g. identity;q=0) is NOT 406'd — identity
        // is sent (RFC 9110 §12.5.3 permits, the common tolerated choice).
        const auto aeIt = req.headers.find("Accept-Encoding");
        const std::string_view acceptEncoding =
          (aeIt != req.headers.end()) ? std::string_view(aeIt->second) : std::string_view{};
        if (out.size() > _compressionThreshold && iora::parsers::gzipAcceptable(acceptEncoding))
        {
          // Compress BEFORE set_content: set_content snapshots Content-Length from
          // content.size() (http_server.hpp:115-131), so compressing first computes
          // Content-Length over the compressed bytes (DP-9/DP-11). Content-Type stays
          // application/json — Content-Encoding modifies the representation; the
          // underlying media type is unchanged (RFC 9110 §8.4).
          std::string compressed = iora::util::Gzip::compress(out);
          res.set_header("Content-Encoding", "gzip");
          res.set_content(std::move(compressed), "application/json");
        }
        else
        {
          res.set_content(std::move(out), "application/json");
        }
      }
      else
      {
        res.set_content(std::move(out), "application/json");
      }

      if (_logRequests)
      {
        iora::core::Logger::debug("JSON-RPC request processed in " +
                                  std::to_string(duration.count()) +
                                  "ms, response size: " + std::to_string(responseSize) + " bytes");
      }
    }
    catch (const std::exception &e)
    {
      iora::core::Logger::error("JSON-RPC internal error: " + std::string(e.what()));
      setJsonRpcError_(res, 500, -32603, "Internal server error");
    }
    catch (...)
    {
      iora::core::Logger::error("JSON-RPC unknown internal error");
      setJsonRpcError_(res, 500, -32603, "Unknown internal error");
    }
  }

  void onUnload() override
  {
    // Nothing to do here, the webhookServer will automatically unmount.
  }

private:
  bool _enabled;
  std::string _path;
  std::size_t _maxRequestBytes;
  std::size_t _maxBatchItems;
  bool _requireAuth;
  int _timeoutMs;
  bool _logRequests;
  bool _enableMetrics;
  // Negotiated gzip compression (Consumer C, arch configSurface.serverFields).
  // enableRequestDecompression gates DECODING only; the request Content-Encoding
  // is EXAMINED regardless (phase 2). The decoded/decompressed-input cap reuses
  // the existing _maxRequestBytes (arch caps.server). Behavior lands in phase 2.
  bool _enableRequestDecompression;
  bool _enableResponseCompression;
  std::size_t _compressionThreshold;

  modules::jsonrpc::JsonRpcServer _router;
};

IORA_DECLARE_PLUGIN(JsonRpcServerPlugin);

} // namespace iora
