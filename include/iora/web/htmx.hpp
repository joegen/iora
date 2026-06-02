// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.
//
// HTMX protocol helpers: eleven pure free functions in iora::web::htmx that
// make iora handlers HTMX-aware. Five REQUEST INSPECTORS read HX-* request
// headers (via the existing Request::get_header_value / has_header); six
// RESPONSE SETTERS write HX-* response headers (via the existing
// Response::set_header). ZERO new types; NO change to HttpServer behavior.
//
// Architecture (source of truth): coding_trackers/architecture/iora/htmx_helpers.json
// Tracker: 2026-05-29-8 (htmx-support phase 7).
//
// SECURITY (M-8 + M-B): Response::set_header (http_server.hpp:122) writes the
// value verbatim with no sanitization. The value-taking setters therefore
// reject CR (0x0D) / LF (0x0A) (rejectCrlf, M-8) before writing; and the two
// URL-valued setters (setRedirect, setPushUrl) additionally reject the
// dangerous URL schemes {javascript:, data:, vbscript:} (rejectDangerousScheme,
// M-B) — both by throwing std::invalid_argument BEFORE set_header. The scheme
// guard rejects dangerous SCHEMES only; it does NOT enforce same-origin /
// open-redirect policy (a scheme-clean cross-origin URL passes — the handler
// owns origin policy).

#pragma once

#include <iora/network/http_server.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace iora
{
namespace web
{
namespace htmx
{

namespace detail
{

/// \brief Reject a value containing CR (0x0D) or LF (0x0A) anywhere (M-8).
/// Throws std::invalid_argument naming \p headerName before any write, closing
/// the HTTP response-splitting / header-injection hole left open by the
/// unsanitized Response::set_header. Inspects raw bytes, so a JSON-escaped
/// "\\n" (0x5C 0x6E) is NOT a newline and passes.
inline void rejectCrlf(const char *headerName, std::string_view value)
{
  for (char ch : value)
  {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (c == 0x0D || c == 0x0A)
    {
      throw std::invalid_argument(std::string(headerName) + " value must not contain CR or LF");
    }
  }
}

/// \brief Reject a value whose URL scheme is one of {javascript, data, vbscript}
/// (M-B). Used by the two URL-valued setters (setRedirect, setPushUrl) AFTER
/// rejectCrlf. Throws std::invalid_argument naming \p headerName before any
/// write.
///
/// Scheme extraction mirrors browser URL parsing (WHATWG / RFC 3986 §3.1):
/// skip leading C0 controls + SPACE (0x00-0x20); the first scheme byte must be
/// an ASCII letter; collect ALPHA / DIGIT / '+' / '-' / '.' IGNORING TAB (0x09)
/// in the scheme region (CR/LF are already rejected upstream) until a ':'
/// terminates the run; ASCII-fold the collected scheme and compare exactly. Any
/// non-scheme byte other than TAB (including NUL and other C0 controls)
/// terminates the run with no ':' found, i.e. NO scheme -> accepted (a browser
/// would not parse such a value as the javascript scheme either). A value with
/// no ALPHA-led ':'-terminated scheme (relative path, fragment, "false",
/// "data-driven/path") is accepted; an ALPHA scheme that folds to a
/// non-dangerous value ("javascript-foo:", bare "javascript", "mailto:") is
/// accepted. EXACT match, not prefix.
///
/// CONTRACT: this guard MUST be called AFTER rejectCrlf. It does NOT itself
/// reject CR/LF — an interior CR/LF would merely terminate the scheme run here
/// (no ':' found -> accepted), yet a browser strips tab/CR/LF across the whole
/// URL before parsing (WHATWG), so "java\nscript:" would execute as the
/// javascript scheme. Because rejectCrlf runs first in every current caller
/// (setRedirect, setPushUrl), no CR/LF ever reaches this function in practice;
/// any FUTURE caller on a navigable-URL sink must preserve that ordering and
/// never use rejectDangerousScheme as the sole guard.
///
/// All byte classification operates on static_cast<unsigned char> with explicit
/// ASCII ranges (NOT locale std::isalpha/std::tolower; the value may contain
/// bytes >= 0x80 and char is signed). The string_view is NOT NUL-terminated;
/// every index is bounds-checked against size().
///
/// SCOPE: rejects dangerous SCHEMES only; does NOT enforce same-origin /
/// open-redirect (a scheme-clean absolute cross-origin URL is accepted).
inline void rejectDangerousScheme(const char *headerName, std::string_view value)
{
  const std::size_t n = value.size();
  std::size_t i = 0;

  // Skip leading C0 controls + SPACE (0x00-0x20). TAB (0x09) is in this range,
  // so a leading TAB is skipped here too.
  while (i < n && static_cast<unsigned char>(value[i]) <= 0x20)
  {
    ++i;
  }
  if (i >= n)
  {
    return; // empty after trim -> no scheme.
  }

  // The first scheme character must be an ASCII letter (RFC 3986 §3.1).
  const unsigned char first = static_cast<unsigned char>(value[i]);
  const bool firstIsAlpha = (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z');
  if (!firstIsAlpha)
  {
    return; // relative path, fragment, etc. -> no scheme.
  }

  std::string scheme;
  bool terminated = false;
  for (std::size_t j = i; j < n; ++j)
  {
    unsigned char c = static_cast<unsigned char>(value[j]);
    if (c == 0x09)
    {
      continue; // ignore TAB within the scheme region.
    }
    if (c == ':')
    {
      terminated = true;
      break;
    }
    const bool isSchemeChar = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
    if (!isSchemeChar)
    {
      break; // any other byte (incl. NUL / other C0 controls) terminates the run.
    }
    if (c >= 'A' && c <= 'Z')
    {
      c = static_cast<unsigned char>(c + 32); // ASCII fold to lowercase.
    }
    scheme.push_back(static_cast<char>(c));
  }

  if (!terminated)
  {
    return; // no ':' -> no scheme.
  }
  if (scheme == "javascript" || scheme == "data" || scheme == "vbscript")
  {
    throw std::invalid_argument(std::string(headerName) + " value uses a forbidden URL scheme");
  }
}

} // namespace detail

// ---------------------------------------------------------------------------
// Request inspectors (total, non-throwing).
// ---------------------------------------------------------------------------

/// \brief True iff the 'HX-Request' header is present and equals the literal
/// lowercase "true" (HTMX always sends lowercase). Absent or any other value
/// -> false. Never throws.
inline bool isHtmx(const iora::network::HttpServer::Request &req)
{
  return req.get_header_value("HX-Request") == "true";
}

/// \brief Value of the 'HX-Trigger' request header (the id of the triggering
/// element). Absent -> std::nullopt; present-but-empty -> optional(""). Never
/// throws.
///
/// CAVEAT (AH-9): HTMX sends 'HX-Trigger' (the id) iff the triggering element
/// has an id, and 'HX-Trigger-Name' (the name) iff it has a name — independently;
/// an element with both attributes sends both headers. So trigger() ==
/// std::nullopt does NOT mean "no element triggered the request" — the element
/// may simply lack an id (it may still expose a name). Check triggerName() too.
/// NOTE (DD-3): this request-side
/// 'HX-Trigger' is unrelated to the response-side 'HX-Trigger' written by
/// setTrigger (same header name, opposite direction).
inline std::optional<std::string> trigger(const iora::network::HttpServer::Request &req)
{
  if (!req.has_header("HX-Trigger"))
  {
    return std::nullopt;
  }
  return req.get_header_value("HX-Trigger");
}

/// \brief Value of the 'HX-Trigger-Name' request header (the name attribute of
/// the triggering element; AH-9). Absent -> std::nullopt; present-but-empty ->
/// optional(""). Never throws.
///
/// WHY THIS EXISTS (id-vs-name caveat): HTMX sends 'HX-Trigger' iff the
/// triggering element has an id and 'HX-Trigger-Name' iff it has a name — the
/// two are independent (an element with both sends both), not alternatives. A
/// handler that must identify the triggering element should prefer trigger()
/// (id) and fall back to triggerName() (name); trigger() == nullopt does not
/// imply "no trigger" (the element may lack an id but still have a name).
inline std::optional<std::string> triggerName(const iora::network::HttpServer::Request &req)
{
  if (!req.has_header("HX-Trigger-Name"))
  {
    return std::nullopt;
  }
  return req.get_header_value("HX-Trigger-Name");
}

/// \brief Value of the 'HX-Target' request header (the id of the target
/// element). Absent -> std::nullopt; present-but-empty -> optional(""). Never
/// throws.
inline std::optional<std::string> target(const iora::network::HttpServer::Request &req)
{
  if (!req.has_header("HX-Target"))
  {
    return std::nullopt;
  }
  return req.get_header_value("HX-Target");
}

/// \brief True iff the 'HX-Boosted' header is present and equals the literal
/// lowercase "true" (set by HTMX for hx-boost'ed requests). Absent or any other
/// value -> false. Never throws.
inline bool isBoost(const iora::network::HttpServer::Request &req)
{
  return req.get_header_value("HX-Boosted") == "true";
}

// ---------------------------------------------------------------------------
// Response setters.
// ---------------------------------------------------------------------------

/// \brief Write 'HX-Redirect: <url>' (HTMX performs a client-side full-page
/// navigation to \p url). Rejects CR/LF (M-8) and the dangerous URL schemes
/// {javascript:, data:, vbscript:} (M-B) by throwing std::invalid_argument
/// before writing.
///
/// SCOPE: validates only CR/LF and the dangerous-scheme set; it does NOT police
/// same-origin / open-redirect — a scheme-clean absolute cross-origin URL is
/// accepted and is the handler's responsibility.
inline void setRedirect(iora::network::HttpServer::Response &res, std::string_view url)
{
  detail::rejectCrlf("HX-Redirect", url);
  detail::rejectDangerousScheme("HX-Redirect", url);
  res.set_header("HX-Redirect", std::string(url));
}

/// \brief Write the constant 'HX-Refresh: true' (HTMX forces a full client-side
/// page reload). Takes no value; no sanitization needed.
inline void setRefresh(iora::network::HttpServer::Response &res)
{
  res.set_header("HX-Refresh", "true");
}

/// \brief Write 'HX-Push-Url: <url>' (HTMX pushes \p url into the browser
/// history/location bar). The literal "false" suppresses the history update.
/// Rejects CR/LF (M-8) and dangerous URL schemes (M-B). Same open-redirect
/// scope note as setRedirect.
inline void setPushUrl(iora::network::HttpServer::Response &res, std::string_view url)
{
  detail::rejectCrlf("HX-Push-Url", url);
  detail::rejectDangerousScheme("HX-Push-Url", url);
  res.set_header("HX-Push-Url", std::string(url));
}

/// \brief Write 'HX-Retarget: <selector>' (a CSS selector overriding the swap
/// target). Rejects CR/LF (M-8). NOT scheme-validated (a CSS selector is not a
/// navigable URL).
inline void setRetarget(iora::network::HttpServer::Response &res, std::string_view selector)
{
  detail::rejectCrlf("HX-Retarget", selector);
  res.set_header("HX-Retarget", std::string(selector));
}

/// \brief Write 'HX-Reswap: <strategy>' (an hx-swap strategy override). Rejects
/// CR/LF (M-8, defense-in-depth — the value may carry caller-composed swap
/// modifiers).
inline void setReswap(iora::network::HttpServer::Response &res, std::string_view strategy)
{
  detail::rejectCrlf("HX-Reswap", strategy);
  res.set_header("HX-Reswap", std::string(strategy));
}

/// \brief Write 'HX-Trigger: <eventOrJson>' (HTMX fires client-side events).
/// The value is an OPAQUE string (DD-5): a bare event name OR a pre-serialized
/// compact JSON object — this helper does NOT build/validate JSON. Rejects
/// CR/LF (M-8) as a JSON-form injection guard; a JSON-escaped "\\n" is two
/// bytes (0x5C 0x6E), not a raw newline, and passes.
///
/// NOTE (DD-3): this response-side 'HX-Trigger' (fire events) is a different
/// concept from the request-side 'HX-Trigger' read by trigger() (the triggering
/// element id); direction disambiguates.
inline void setTrigger(iora::network::HttpServer::Response &res, std::string_view eventOrJson)
{
  detail::rejectCrlf("HX-Trigger", eventOrJson);
  res.set_header("HX-Trigger", std::string(eventOrJson));
}

} // namespace htmx
} // namespace web
} // namespace iora
