// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/core/logger.hpp"
#include "iora/network/http_server.hpp"
#include "iora/util/base64.hpp"

#include <cstddef>
#include <functional>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

namespace iora
{
namespace network
{

namespace detail
{
/// \brief Best-effort overwrite of a std::string's buffer so a decoded
/// credential does not linger in freed heap memory (defense-in-depth — not a
/// substitute for TLS, and it cannot cover copies the verify callback retains).
/// The writes go through a volatile pointer so the compiler may not elide them.
inline void secureZero(std::string &s)
{
  if (!s.empty())
  {
    volatile char *p = s.data();
    for (std::size_t i = 0; i < s.size(); ++i)
    {
      p[i] = '\0';
    }
  }
  s.clear();
}

/// \brief RAII scrubber: wipes a set of credential-bearing strings on scope
/// exit — covers every early return AND an exception propagating out of the
/// inner handler.
class CredentialScrubber
{
public:
  explicit CredentialScrubber(std::initializer_list<std::string *> fields)
    : _fields(fields)
  {
  }
  CredentialScrubber(const CredentialScrubber &) = delete;
  CredentialScrubber &operator=(const CredentialScrubber &) = delete;
  ~CredentialScrubber()
  {
    for (std::string *f : _fields)
    {
      secureZero(*f);
    }
  }

private:
  std::vector<std::string *> _fields;
};
} // namespace detail

/// \brief Decorate any HttpServer::Handler with HTTP Basic authentication.
///
/// Returns a Handler that challenges unauthenticated requests with
/// 401 + `WWW-Authenticate: Basic realm="<realm>"`, decodes the
/// `Authorization: Basic <base64(user:pass)>` credential, splits it on the
/// first ':' into user/pass, calls the caller-supplied \p verify predicate, and
/// runs \p inner only when verify returns true. It is a pure decorator over the
/// existing Handler typedef — no new handler type and no change to HttpServer
/// dispatch — so it composes with onGet/onPost, pattern routes, and the routing
/// safety-net.
///
/// Behavior (RFC 7617 / RFC 9110 §11):
///   - Missing/empty Authorization, a non-Basic scheme, a tab separator, an
///     undecodable credential, or a credential without ':' all produce a 401
///     re-challenge (not a 400). The scheme token "Basic" is matched
///     case-insensitively and must be followed by 1*SP (one or more spaces,
///     0x20); a HTAB after the scheme is non-conformant and rejected.
///   - The credential token is SP/HTAB-trimmed (leniency restricted to 0x20 /
///     0x09; CR/LF and '=' padding are never trimmed) before Base64 decode.
///   - A \p verify that throws is caught and mapped to 500; the protected
///     \p inner's exceptions are NOT caught here — they propagate to the
///     routing safety-net.
///
/// \param realm The Basic realm shown to the client. Sanitized once at
///   construction: a realm containing any control byte (< 0x20, including CR and
///   LF), DEL (0x7F), '"', or '\\' throws std::invalid_argument. CR/LF would
///   inject a response header; '"' and '\\' would break out of the quoted-string;
///   the remaining control bytes and DEL are not valid quoted-string `qdtext`
///   (RFC 9110 §5.6.4), so rejecting them keeps the emitted realm a clean,
///   well-formed quoted-string. Captured by value into the returned closure.
/// \param verify Caller-supplied predicate returning true iff (user,pass) are
///   valid. iora never stores, hashes, or compares credentials itself — that is
///   entirely the caller's responsibility. SECURITY: \p verify MUST use a
///   constant-time comparison (and any hashing) to avoid timing attacks, and
///   requireBasicAuth MUST be used behind TLS only — HTTP Basic transmits
///   credentials as cleartext-equivalent Base64 (RFC 7617 §4). The decoded
///   user-id and password are never logged.
/// \param inner The protected Handler, run only after \p verify returns true.
/// \return An HttpServer::Handler suitable for registration on any route.
/// \throws std::invalid_argument if \p realm contains a control byte (< 0x20),
///   DEL (0x7F), '"', or '\\'.
///
/// \note The pre-verify rejection paths (missing/short header, non-Basic scheme,
///   undecodable credential, missing colon) are intentionally NOT constant-time:
///   the structural validity of an Authorization header is not secret. Constant-
///   time secrecy is the \p verify callback's responsibility (see above).
inline HttpServer::Handler requireBasicAuth(
  std::string realm,
  std::function<bool(const std::string &user, const std::string &pass)> verify,
  HttpServer::Handler inner)
{
  // Construction-time realm sanitization (M-8 / D-2, widened per code-review
  // M-2): reject '"' and '\\' (quoted-string breakout), and every control byte
  // (< 0x20, which includes CR/LF — the header-injection vector) plus DEL
  // (0x7F), none of which are valid quoted-string qdtext (RFC 9110 §5.6.4).
  for (char c : realm)
  {
    const auto uc = static_cast<unsigned char>(c);
    if (uc < 0x20 || uc == 0x7F || c == '"' || c == '\\')
    {
      throw std::invalid_argument(
        "requireBasicAuth: realm must not contain control bytes, DEL, '\"', or "
        "'\\'");
    }
  }

  return [realm = std::move(realm), verify = std::move(verify),
          inner = std::move(inner)](const HttpServer::Request &req,
                                    HttpServer::Response &res)
  {
    const auto emit401 = [&]()
    {
      res.status = 401;
      // Built lazily here (only on a challenge), not on the success path.
      res.set_header("WWW-Authenticate", "Basic realm=\"" + realm + "\"");
      res.set_content("Unauthorized", "text/plain");
    };
    const auto emit500 = [&]()
    {
      res.status = 500;
      res.set_content("Internal Server Error", "text/plain");
    };

    // 1. Read the Authorization header (returns std::string by value; bind to a
    //    named variable so the std::string_view passed to decode does not
    //    dangle). An empty value is treated identically to an absent header.
    std::string auth = req.get_header_value("Authorization");

    // Credential-bearing locals, declared up front so the scrubber covers every
    // exit path (early returns AND an exception propagating from inner). The
    // strings are wiped best-effort on scope exit (defense-in-depth).
    std::string token;
    std::string cred;
    std::string user;
    std::string pass;
    detail::CredentialScrubber scrub{&auth, &token, &cred, &user, &pass};

    // 2. Match the credentials grammar: case-insensitive "Basic" + 1*SP (RFC
    //    7235 §2.1). SP is 0x20 only (RFC 5234 App B.1 core rule); HTAB after
    //    the scheme is non-conformant.
    static constexpr char kScheme[] = "Basic";
    static constexpr std::size_t kSchemeLen = sizeof(kScheme) - 1;
    if (auth.size() < kSchemeLen)
    {
      emit401();
      return;
    }
    // ASCII-only case fold (deliberately not std::tolower, which is locale-
    // sensitive and UB on a negative char): the scheme token is bounded ASCII.
    for (std::size_t i = 0; i < kSchemeLen; ++i)
    {
      char a = auth[i];
      if (a >= 'A' && a <= 'Z')
      {
        a = static_cast<char>(a - 'A' + 'a');
      }
      char b = kScheme[i];
      if (b >= 'A' && b <= 'Z')
      {
        b = static_cast<char>(b - 'A' + 'a');
      }
      if (a != b)
      {
        emit401();
        return;
      }
    }
    // The scheme must be followed by 1*SP. Requiring an SP here also makes the
    // scheme token-bounded: "BasicX" fails (position 5 is 'X', not SP) and
    // "Basic" with no separator fails (no char after the scheme).
    std::size_t pos = kSchemeLen;
    if (pos >= auth.size() || auth[pos] != ' ')
    {
      emit401();
      return;
    }
    while (pos < auth.size() && auth[pos] == ' ')
    {
      ++pos;
    }

    // 3. Extract the credential token and trim surrounding SP/HTAB (M-B
    //    leniency: 0x20/0x09 only — never CR/LF, never '=' padding).
    std::size_t tokBegin = pos;
    std::size_t tokEnd = auth.size();
    while (tokBegin < tokEnd && (auth[tokBegin] == ' ' || auth[tokBegin] == '\t'))
    {
      ++tokBegin;
    }
    while (tokEnd > tokBegin &&
           (auth[tokEnd - 1] == ' ' || auth[tokEnd - 1] == '\t'))
    {
      --tokEnd;
    }
    token = auth.substr(tokBegin, tokEnd - tokBegin);

    // 4. Decode the token (standard alphabet). Undecodable -> 401 (D-3).
    const auto bytes = util::Base64::decode(token);
    if (!bytes)
    {
      emit401();
      return;
    }

    // 5. Split on the FIRST ':' into user/pass; no ':' -> 401 (RFC 7617: the
    //    user-id MUST NOT contain ':'; the password MAY).
    cred.assign(bytes->begin(), bytes->end());
    const std::size_t colon = cred.find(':');
    if (colon == std::string::npos)
    {
      emit401();
      return;
    }
    user = cred.substr(0, colon);
    pass = cred.substr(colon + 1);

    // 6. Call verify inside try/catch. A throw -> 500 + ERROR log of the
    //    exception message ONLY (never the credential — HR-9).
    bool ok = false;
    try
    {
      ok = verify(user, pass);
    }
    catch (const std::exception &e)
    {
      emit500();
      IORA_LOG_ERROR(std::string("requireBasicAuth: verify callback threw: ") +
                     e.what());
      return;
    }
    catch (...)
    {
      emit500();
      IORA_LOG_ERROR(
        "requireBasicAuth: verify callback threw a non-std::exception");
      return;
    }

    // 7. verify false -> 401 re-challenge.
    if (!ok)
    {
      emit401();
      return;
    }

    // 8. Run the protected handler. Its exceptions are NOT caught here — they
    //    propagate to the routing safety-net (routing_extension.json M-1).
    inner(req, res);
  };
}

} // namespace network
} // namespace iora
