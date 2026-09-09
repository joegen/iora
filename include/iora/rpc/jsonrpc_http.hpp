// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <cstddef>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "iora/core/logger.hpp"
#include "iora/core/string_utils.hpp"
#include "iora/network/http_server.hpp"
#include "iora/parsers/accept_encoding.hpp"
#include "iora/parsers/content_coding.hpp"
#include "iora/rpc/jsonrpc_server.hpp"
#include "iora/util/gzip.hpp"

namespace iora
{
namespace rpc
{

/// \brief HTTP-transport refusal codes (D-ERRCODE). Distinct from the protocol
/// ErrorCode in jsonrpc_server.hpp: these cover requests that never reached the
/// JSON-RPC parser (415/413/400), so they MUST NOT reuse -32600 ("not a valid
/// Request object" — the body was never parsed). JSON-RPC 2.0 §5.1 reserves
/// -32000..-32099 for implementation-defined server errors; every transport
/// refusal envelope is built from static_cast<int>(HttpErrorCode::X).
enum class HttpErrorCode : int
{
  UnsupportedMediaType = -32015, ///< 415: bad Content-Type essence, or an undecodable/over-cap Content-Encoding
  EntityTooLarge = -32013,       ///< 413: raw body or post-inflate body over maxRequestBytes
  BadCoding = -32040             ///< 400: a Content-Encoding declared gzip but the body failed to inflate
};

/// \brief Configuration for the JSON-RPC-over-HTTP endpoint. Passed by value; the
/// registered handler owns its own copy. Deliberately carries NO allowedOrigins /
/// CORS field — tracker A introduces CORS together with the handler that consumes
/// it, so B ships no inert option.
struct JsonRpcHttpOptions
{
  std::string path{"/rpc"};
  std::size_t maxRequestBytes{1048576};
  std::size_t maxBatchItems{50};
  bool requireAuth{false};
  bool logRequests{false};

  /// \brief D-AUTH: returns the authenticated subject on success, nullopt on
  /// rejection. When requireAuth && !tokenValidator the endpoint FAILS CLOSED
  /// (every request 401s). Kept as an option (not a foundation decorator) so the
  /// RFC 6750/9110 bearer grammar stays inline and testable via the static handle().
  std::function<std::optional<std::string>(std::string_view token)> tokenValidator;

  /// \brief Interpolated into WWW-Authenticate. Validated against the qdtext reject
  /// set (matching http_auth.hpp) before interpolation — an invalid realm is a
  /// server misconfiguration (the constructor throws) and is never emitted.
  std::string authRealm;

  // Consumer C negotiated gzip. enableRequestDecompression gates only DECODING;
  // the request Content-Encoding is examined regardless.
  bool enableRequestDecompression{false};
  bool enableResponseCompression{false};
  std::size_t compressionThreshold{1024};
};

/// \brief Binds a JsonRpcServer to a network::HttpServer as an HTTP POST endpoint,
/// re-deriving the JSON-RPC-over-HTTP status-code mapping from the specifications
/// (RFC 9110 / RFC 6750 / JSON-RPC 2.0), not carried over bug-for-bug from the
/// former plugin.
///
/// \par Lifetime (D-LIFETIME, raw-pointer form)
/// The registered handler captures a RAW JsonRpcServer* (from \c &server) and an
/// OWNED BY-VALUE COPY of the options — never \c this, never a weak_ptr/shared_ptr.
/// TESTED PRECONDITION: the JsonRpcServer must be declared before the HttpServer,
/// and HttpServer::stop() must complete before the JsonRpcServer — or any state
/// the handler/options depend on, including tokenValidator's captured state — is
/// destroyed. stop() is NOT a hard barrier (it abandons its drain after 2 s), so
/// post-destruction dispatch is UNDEFINED BEHAVIOUR; the teardown-race UAF is
/// accepted with this documented + tested (task-8.1) mitigation. An application
/// needing a hard guarantee can adopt a weak_ptr shared-state form as a usage
/// pattern.
///
/// \par Static handle()
/// Exposed as a static over the plain Request/Response structs so every status
/// path is unit-testable with no socket.
class JsonRpcHttpEndpoint
{
public:
  /// \brief Register the endpoint on \p http at \c options.path. Does NOT own or
  /// start the HttpServer. Registers LAST so nothing is published into a live
  /// dispatching server mid-construction.
  JsonRpcHttpEndpoint(JsonRpcServer &server, network::HttpServer &http,
                      JsonRpcHttpOptions options = {})
  {
    if (!isValidRealm(options.authRealm))
    {
      throw std::invalid_argument(
        "JsonRpcHttpEndpoint: authRealm must not contain control bytes, DEL, '\"', or '\\'");
    }

    JsonRpcServer *serverPtr = &server;
    const std::string registerPath = options.path;
    http.onPost(registerPath,
                [serverPtr, opts = std::move(options)](const network::HttpServer::Request &req,
                                                        network::HttpServer::Response &res)
                { handle(*serverPtr, req, res, opts); });
  }

  // A registration RAII token is not meaningfully copyable or movable: a
  // memberwise copy would NOT re-run onPost and would produce an inert duplicate
  // endpoint that registers nothing (HttpServer has no unregister API), silently
  // masking mis-use. Delete all four so the class cannot be stored in a container.
  JsonRpcHttpEndpoint(const JsonRpcHttpEndpoint &) = delete;
  JsonRpcHttpEndpoint &operator=(const JsonRpcHttpEndpoint &) = delete;
  JsonRpcHttpEndpoint(JsonRpcHttpEndpoint &&) = delete;
  JsonRpcHttpEndpoint &operator=(JsonRpcHttpEndpoint &&) = delete;

  /// \brief The complete JSON-RPC-over-HTTP mapping. PINNED order (A-web D):
  /// media-type(415) -> raw-size(413) -> auth(401) -> content-encoding(415/413/400)
  /// -> dispatch. Content-Encoding handling MUST follow auth so an unauthenticated
  /// caller cannot force decompression CPU or probe supported codings pre-auth.
  static void handle(JsonRpcServer &server, const network::HttpServer::Request &req,
                     network::HttpServer::Response &res, const JsonRpcHttpOptions &options)
  {
    // ── 1. Media type (RFC 9110 §8.3 / D-MEDIA). Allow-list of exact essences;
    // NOT a substring match (CR-8: 'text/plain;x=application/json' has a
    // CORS-safelisted essence). The media-type 415 deliberately carries NO
    // Accept-Encoding (that header disambiguates the content-coding 415 below).
    {
      auto it = req.headers.find("Content-Type");
      if (it == req.headers.end() || !isAcceptedMediaType(it->second))
      {
        writeTransportError(res, 415, HttpErrorCode::UnsupportedMediaType, "Unsupported Media Type");
        if (options.logRequests)
        {
          IORA_LOG_WARN("JSON-RPC request rejected: unsupported media type");
        }
        return;
      }
    }

    // ── 2. Raw size (RFC 9110 §15.5.14). A fixed limit is permanent, so NO
    // Retry-After. The body is NOT dispatched.
    if (req.body.size() > options.maxRequestBytes)
    {
      writeTransportError(res, 413, HttpErrorCode::EntityTooLarge, "Content Too Large");
      if (options.logRequests)
      {
        IORA_LOG_WARN("JSON-RPC request rejected: body size "
                      << req.body.size() << " exceeds limit " << options.maxRequestBytes);
      }
      return;
    }

    // ── 3. Auth (D-AUTH, RFC 6750/9110). FAIL-CLOSED: requireAuth && no validator
    // -> 401. Every 401 carries WWW-Authenticate; error="invalid_token" ONLY when a
    // syntactically-valid bearer token was supplied and the validator rejected it
    // (RFC 6750 §3 / §3.1) — an absent header, unsupported scheme, or malformed
    // grammar carries no error= param.
    std::optional<std::string> subject;
    if (options.requireAuth)
    {
      if (!options.tokenValidator)
      {
        writeAuthChallenge(res, options.authRealm, /*rejectedToken=*/false);
        if (options.logRequests)
        {
          IORA_LOG_WARN("JSON-RPC request rejected: auth required but no validator (fail-closed)");
        }
        return;
      }

      std::optional<std::string> token;
      auto authIt = req.headers.find("Authorization");
      if (authIt != req.headers.end())
      {
        token = parseBearerToken(authIt->second);
      }

      if (!token)
      {
        writeAuthChallenge(res, options.authRealm, /*rejectedToken=*/false);
        if (options.logRequests)
        {
          IORA_LOG_WARN("JSON-RPC request rejected: missing or malformed bearer credentials");
        }
        return;
      }

      subject = options.tokenValidator(*token);
      if (!subject)
      {
        writeAuthChallenge(res, options.authRealm, /*rejectedToken=*/true);
        if (options.logRequests)
        {
          IORA_LOG_WARN("JSON-RPC request rejected: bearer token not accepted");
        }
        return;
      }
    }

    // ── 4. Request Content-Encoding (Consumer C, DP-6/DP-7). AFTER auth. The body
    // handed to the dispatcher: req.body on the common (no-coding/identity) path
    // with no copy; a locally-owned inflated buffer only when we decode gzip.
    const std::string *bodyForDispatch = &req.body;
    std::string decoded;
    {
      const auto ceIt = req.headers.find("Content-Encoding");
      if (ceIt != req.headers.end())
      {
        const std::vector<std::string> codings = parsers::splitContentCodings(ceIt->second);
        if (!codings.empty())
        {
          // <=2 hard cap on the TOTAL list length: bounds stacked-inflate CPU and
          // rejects an 'identity,...,gzip' padding attack. gzip/x-gzip is decodable
          // only when enableRequestDecompression; identity always is.
          bool hasGzip = false;
          bool decodable = codings.size() <= 2;
          if (decodable)
          {
            for (const auto &c : codings)
            {
              if (core::StringUtils::iequals(c, "identity"))
              {
                continue;
              }
              if (parsers::isGzipContentCoding(c))
              {
                hasGzip = true;
                continue;
              }
              decodable = false;
              break;
            }
          }

          if (!decodable || (hasGzip && !options.enableRequestDecompression))
          {
            // Content-coding 415 carries Accept-Encoding listing the decodable set
            // (DP-7) — this is what makes a client's latch-off fire instead of a
            // silent 200 + parse error.
            res.set_header("Accept-Encoding",
                           options.enableRequestDecompression ? "gzip, identity" : "identity");
            writeTransportError(res, 415, HttpErrorCode::UnsupportedMediaType,
                                "Unsupported Content-Encoding");
            if (options.logRequests)
            {
              IORA_LOG_WARN("JSON-RPC request rejected: undecodable Content-Encoding '"
                            << parsers::sanitizeCodingForLog(ceIt->second) << "'");
            }
            return;
          }

          if (hasGzip)
          {
            // Decode outermost-first (reverse of applied order); each inflate is
            // bounded to maxRequestBytes. OUTPUT_TOO_LARGE -> 413, MALFORMED -> 400.
            decoded = req.body;
            for (auto rit = codings.rbegin(); rit != codings.rend(); ++rit)
            {
              if (core::StringUtils::iequals(*rit, "identity"))
              {
                continue;
              }
              auto r = util::Gzip::decompress(decoded, options.maxRequestBytes);
              if (!r.isOk())
              {
                if (r.error() == util::Gzip::DecompressError::OUTPUT_TOO_LARGE)
                {
                  writeTransportError(res, 413, HttpErrorCode::EntityTooLarge, "Content Too Large");
                }
                else
                {
                  writeTransportError(res, 400, HttpErrorCode::BadCoding,
                                      "Malformed Content-Encoding");
                }
                return;
              }
              decoded = std::move(r).value();
            }
            bodyForDispatch = &decoded;
          }
        }
      }
    }

    // ── 5. Dispatch.
    RpcContext ctx(subject);
    ctx.metadata().clientId = req.remote_addr; // D-1: real peer address, not "unknown"

    try
    {
      std::string out = server.handleRequest(*bodyForDispatch, ctx, options.maxBatchItems);

      if (out.empty())
      {
        // Notification-only request or all-notification batch. 204 MUST carry no
        // content (RFC 9110 §15.3.5 / RFC 9112 §6.3). Belt-and-braces regardless of
        // any dispatcher-side clear: erase body + framing/type headers.
        res.status = 204;
        res.body.clear();
        res.headers.erase("Content-Length");
        res.headers.erase("Content-Type");
        return;
      }

      res.status = 200;
      writeSuccess(res, std::move(out), req, options);
    }
    catch (const std::exception &)
    {
      // Handler exceptions frequently embed request-derived strings/token fragments,
      // so log a stable class and the SANITIZED method — never raw what(). The method
      // is attacker-controlled and unbounded, so scrub it with the foundation log
      // scrubber (parsers::sanitizeCodingForLog: keeps printable ASCII, folds ALL
      // whitespace incl. CR/LF to space, drops every other control octet, bounds to
      // 128 chars) rather than a CR/LF-only strip (Slice-A review SA-1). This 500 log
      // is intentionally UNCONDITIONAL (unlike the logRequests-gated rejection warns) —
      // a server fault must always be visible (Slice-A review CA-2).
      IORA_LOG_ERROR("JSON-RPC internal error [std::exception] dispatching method '"
                     << parsers::sanitizeCodingForLog(ctx.metadata().method) << "'");
      writeInternalError(res);
    }
    catch (...)
    {
      IORA_LOG_ERROR("JSON-RPC internal error [unknown] dispatching method '"
                     << parsers::sanitizeCodingForLog(ctx.metadata().method) << "'");
      writeInternalError(res);
    }
  }

private:
  // ── Media type ────────────────────────────────────────────────────────────
  /// \brief RFC 9110 §8.3 essence match against the D-MEDIA allow-list. Take the
  /// substring before the first ';', OWS-trim both ends, ASCII-lowercase, then
  /// require an exact essence — {application/json, application/json-rpc,
  /// application/jsonrequest}. The charset parameter is ignored (essence only);
  /// generic '*+json' structured suffixes are rejected (YAGNI).
  /// \brief Trim RFC 9110 OWS (SP / HTAB ONLY) at both ends (Slice-A review SA-4).
  /// Deliberately NOT core::StringUtils::trim, which also strips CR/LF — the HTTP
  /// grammar here permits only SP/HTAB as optional whitespace.
  static std::string_view trimOws(std::string_view sv)
  {
    while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t'))
    {
      sv.remove_prefix(1);
    }
    while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t'))
    {
      sv.remove_suffix(1);
    }
    return sv;
  }

  static bool isAcceptedMediaType(std::string_view contentType)
  {
    const std::string_view essence = trimOws(contentType.substr(0, contentType.find(';')));
    return core::StringUtils::iequals(essence, "application/json") ||
           core::StringUtils::iequals(essence, "application/json-rpc") ||
           core::StringUtils::iequals(essence, "application/jsonrequest");
  }

  // ── Auth ─────────────────────────────────────────────────────────────────
  /// \brief RFC 6750 token68 charset: 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" /
  /// "+" / "/" ) *"=". Non-empty; '=' only as trailing padding.
  static bool isToken68(std::string_view t)
  {
    if (t.empty())
    {
      return false;
    }
    bool sawPadding = false;
    bool sawNonPad = false;
    for (char c : t)
    {
      if (c == '=')
      {
        sawPadding = true;
        continue;
      }
      if (sawPadding)
      {
        return false; // a non-'=' after '=' padding
      }
      const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                      c == '~' || c == '+' || c == '/';
      if (!ok)
      {
        return false;
      }
      sawNonPad = true;
    }
    return sawNonPad;
  }

  /// \brief Parse an Authorization value as a bearer credential. Scheme match is
  /// case-insensitive (RFC 9110 §11.1); the separator is 1*SP (0x20 only — a HTAB
  /// after the scheme is non-conformant, RFC 9110 §11.6.2); trailing OWS is
  /// stripped; the token is token68-validated. Returns the token on success.
  static std::optional<std::string> parseBearerToken(std::string_view v)
  {
    std::size_t p = 0;
    while (p < v.size() && v[p] != ' ' && v[p] != '\t')
    {
      ++p;
    }
    if (p == 0 || p >= v.size())
    {
      return std::nullopt; // no scheme, or no separator
    }
    if (!core::StringUtils::iequals(v.substr(0, p), "Bearer"))
    {
      return std::nullopt;
    }
    if (v[p] != ' ')
    {
      return std::nullopt; // separator must be SP (1*SP), not HTAB
    }
    while (p < v.size() && v[p] == ' ')
    {
      ++p;
    }
    const std::string_view rest = trimOws(v.substr(p)); // trailing OWS (SA-4)
    if (!isToken68(rest))
    {
      return std::nullopt;
    }
    return std::string(rest);
  }

  /// \brief The qdtext reject set (RFC 9110 §5.6.4), matching http_auth.hpp: reject
  /// a char when it is '"', '\\', a control byte (< 0x20), or DEL (0x7F). An empty
  /// realm is valid (no bad chars).
  static bool isValidRealm(std::string_view realm)
  {
    for (char c : realm)
    {
      const auto uc = static_cast<unsigned char>(c);
      if (uc < 0x20 || uc == 0x7F || c == '"' || c == '\\')
      {
        return false;
      }
    }
    return true;
  }

  static void writeAuthChallenge(network::HttpServer::Response &res, const std::string &authRealm,
                                 bool rejectedToken)
  {
    // Defensive: never interpolate an invalid realm (the ctor already rejects one,
    // but handle() is a static reachable directly with unvalidated options). Compute
    // the realm-usability predicate ONCE (Slice-A review SA-3).
    const bool realmUsable = !authRealm.empty() && isValidRealm(authRealm);
    std::string challenge = "Bearer";
    if (realmUsable)
    {
      challenge += " realm=\"" + authRealm + "\"";
    }
    if (rejectedToken)
    {
      challenge += realmUsable ? ", " : " ";
      challenge += "error=\"invalid_token\"";
    }
    res.set_header("WWW-Authenticate", challenge);
    writeEnvelope(res, 401, static_cast<int>(ErrorCode::AuthenticationError),
                  "Authentication required");
  }

  // ── Envelope helpers ───────────────────────────────────────────────────────
  /// \brief A transport-refusal envelope carries the endpoint-local HttpErrorCode
  /// (never -32600, W-M1).
  static void writeTransportError(network::HttpServer::Response &res, int status,
                                  HttpErrorCode code, const std::string &message)
  {
    writeEnvelope(res, status, static_cast<int>(code), message);
  }

  static void writeInternalError(network::HttpServer::Response &res)
  {
    writeEnvelope(res, 500, static_cast<int>(ErrorCode::InternalError), "Internal server error");
  }

  /// \brief Emit a JSON-RPC 2.0 error envelope. Every error body stays identity —
  /// defensively erase Content-Encoding/Vary so a throw that unwinds after response
  /// compression began cannot leak a stray gzip header onto the error (mirrors the
  /// former plugin's setJsonRpcError_ hygiene).
  static void writeEnvelope(network::HttpServer::Response &res, int status, int code,
                            const std::string &message)
  {
    res.status = status;
    res.headers.erase("Content-Encoding");
    res.headers.erase("Vary");
    auto error = parsers::Json::object();
    error["code"] = code;
    error["message"] = message;
    auto envelope = parsers::Json::object();
    envelope["jsonrpc"] = "2.0";
    envelope["error"] = std::move(error);
    envelope["id"] = parsers::Json(); // null
    res.set_content(envelope.dump(), "application/json");
  }

  // ── Success + response compression (Consumer C) ─────────────────────────────
  static void writeSuccess(network::HttpServer::Response &res, std::string out,
                           const network::HttpServer::Request &req,
                           const JsonRpcHttpOptions &options)
  {
    if (!options.enableResponseCompression)
    {
      res.set_content(std::move(out), "application/json");
      return;
    }

    // A content-negotiated 200 varies by Accept-Encoding: advertise Vary on EVERY
    // negotiated 200 (compressed, identity-negotiated, and no-Accept-Encoding) for
    // cache correctness (RFC 9110 §12.5.5).
    res.set_header("Vary", "Accept-Encoding");

    const auto aeIt = req.headers.find("Accept-Encoding");
    const std::string_view acceptEncoding =
      (aeIt != req.headers.end()) ? std::string_view(aeIt->second) : std::string_view{};
    if (out.size() > options.compressionThreshold && parsers::gzipAcceptable(acceptEncoding))
    {
      // Compress BEFORE set_content so Content-Length is over the compressed bytes.
      // Content-Type stays application/json — Content-Encoding modifies the
      // representation, not the media type (RFC 9110 §8.4).
      std::string compressed = util::Gzip::compress(out);
      res.set_header("Content-Encoding", "gzip");
      res.set_content(std::move(compressed), "application/json");
    }
    else
    {
      res.set_content(std::move(out), "application/json");
    }
  }

};

} // namespace rpc
} // namespace iora
