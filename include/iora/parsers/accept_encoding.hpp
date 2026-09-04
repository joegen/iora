// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <cstddef>
#include <optional>
#include <string_view>

/// \file accept_encoding.hpp
/// \brief RFC 9110 §12.5.3 Accept-Encoding acceptability primitive (gzip).
///
/// A shared header-parsing primitive that sits beside parsers/http_message.hpp:
/// both the web application framework (web/application.hpp static-asset serving)
/// and the endpoint/connector modules (mod_jsonrpc_server response negotiation)
/// need the SAME q-value-correct "is gzip acceptable?" decision over an
/// Accept-Encoding header value. It was originally a PRIVATE static member of
/// iora::web::Application; promoting it here (rather than to iora/web/) keeps an
/// endpoint module from reaching UP into the application-framework layer.
///
/// Deliberately gzip-SPECIFIC (a boolean gzipAcceptable), NOT generalized to a
/// codingAcceptable(ae, coding) — only gzip is negotiated across iora, and a
/// premature generalization would be unused surface (YAGNI).

namespace iora
{
namespace parsers
{

/// \brief Internal character/token helpers for the Accept-Encoding q-value parse.
/// A dedicated namespace (not the shared parsers::detail) so these do not collide
/// with the helpers of sibling parser headers.
namespace acceptencoding_detail
{

inline bool isOws(char c) { return c == ' ' || c == '\t'; }

inline std::string_view trimView(std::string_view s)
{
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && isOws(s[b]))
  {
    ++b;
  }
  while (e > b && isOws(s[e - 1]))
  {
    --e;
  }
  return s.substr(b, e - b);
}

inline char asciiLower(char c)
{
  const unsigned char u = static_cast<unsigned char>(c);
  if (u >= 'A' && u <= 'Z')
  {
    return static_cast<char>(u - 'A' + 'a');
  }
  return c;
}

inline bool asciiIEquals(std::string_view a, std::string_view b)
{
  if (a.size() != b.size())
  {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i)
  {
    const char ca = asciiLower(a[i]);
    const char cb = asciiLower(b[i]);
    if (ca != cb)
    {
      return false;
    }
  }
  return true;
}

/// \brief Locale-INDEPENDENT RFC 9110 §12.5.3 qvalue parse: ( "0" [ "."
/// 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] ). Returns the value in [0,1], or
/// 0.0 for any malformed / out-of-range input (NOT std::stod, which is
/// locale-sensitive and accepts scientific/out-of-range forms).
inline double parseQValue(std::string_view v)
{
  if (v.empty())
  {
    return 0.0;
  }
  double whole;
  if (v[0] == '0')
  {
    whole = 0.0;
  }
  else if (v[0] == '1')
  {
    whole = 1.0;
  }
  else
  {
    return 0.0; // invalid leading digit
  }
  double frac = 0.0;
  double scale = 0.1;
  std::size_t i = 1;
  if (i < v.size())
  {
    if (v[i] != '.')
    {
      return 0.0; // junk after the leading digit
    }
    ++i;
    int digits = 0;
    for (; i < v.size(); ++i, ++digits)
    {
      const char c = v[i];
      if (c < '0' || c > '9' || digits >= 3)
      {
        return 0.0; // non-digit or >3 fractional digits (grammar violation)
      }
      frac += static_cast<double>(c - '0') * scale;
      scale *= 0.1;
    }
  }
  const double q = whole + frac;
  if (q > 1.0)
  {
    return 0.0; // out of range (e.g. "1.5") is invalid -> not acceptable
  }
  return q;
}

/// \brief Parse the q-value from a ';'-separated parameter list. Absent q ->
/// 1.0 (a coding with no q defaults to q=1, RFC 9110 §12.5.3). A present but
/// MALFORMED / out-of-range q -> 0.0 (treated as not-acceptable, the
/// conservative choice — a garbage q must never enable a coding).
inline double qValueOf(std::string_view params)
{
  std::size_t pos = 0;
  while (pos <= params.size())
  {
    const std::size_t semi = params.find(';', pos);
    const std::string_view param =
      (semi == std::string_view::npos) ? params.substr(pos) : params.substr(pos, semi - pos);
    pos = (semi == std::string_view::npos) ? params.size() + 1 : semi + 1;

    const std::size_t eq = param.find('=');
    if (eq == std::string_view::npos)
    {
      continue;
    }
    const std::string_view name = trimView(param.substr(0, eq));
    if (asciiIEquals(name, "q"))
    {
      return parseQValue(trimView(param.substr(eq + 1)));
    }
  }
  return 1.0; // no explicit q -> q=1
}

} // namespace acceptencoding_detail

/// \brief RFC 9110 §12.5.3 Accept-Encoding acceptability for gzip (q-values).
/// gzip acceptable iff an explicit 'gzip' entry (else '*') has a non-zero
/// qvalue; absent header / empty header / q=0 -> identity (NOT acceptable). NOT a
/// naive contains() (which misses q=0, ordering, and the '*' fallback).
///
/// Both an ABSENT Accept-Encoding and an EMPTY Accept-Encoding resolve to
/// identity here (return false): RFC 9110 §12.5.3 permits a server to send
/// identity when the field is absent, so callers must NOT "fix" this to
/// always-gzip-on-absent.
inline bool gzipAcceptable(std::string_view acceptEncoding)
{
  namespace d = acceptencoding_detail;
  if (d::trimView(acceptEncoding).empty())
  {
    return false;
  }
  std::optional<double> gzipQ;
  std::optional<double> starQ;
  std::size_t pos = 0;
  while (pos <= acceptEncoding.size())
  {
    const std::size_t comma = acceptEncoding.find(',', pos);
    const std::string_view entry = (comma == std::string_view::npos)
                                     ? acceptEncoding.substr(pos)
                                     : acceptEncoding.substr(pos, comma - pos);
    pos = (comma == std::string_view::npos) ? acceptEncoding.size() + 1 : comma + 1;

    const std::size_t semi = entry.find(';');
    const std::string_view coding = d::trimView(entry.substr(0, semi));
    double q = 1.0;
    if (semi != std::string_view::npos)
    {
      q = d::qValueOf(entry.substr(semi + 1));
    }
    if (d::asciiIEquals(coding, "gzip"))
    {
      gzipQ = q;
    }
    else if (coding == "*")
    {
      starQ = q;
    }
  }
  const double eff = gzipQ ? *gzipQ : (starQ ? *starQ : 0.0);
  return eff > 0.0;
}

} // namespace parsers
} // namespace iora
