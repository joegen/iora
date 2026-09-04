// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "iora/core/string_utils.hpp"

/// \file content_coding.hpp
/// \brief RFC 9110 §8.4 Content-Encoding list-splitting primitive.
///
/// Content-Encoding (and, symmetrically, Accept-Encoding) is a list-valued field
/// (RFC 9110 §5.3/§8.4): duplicate field-lines COMBINE with a comma, and the
/// combined value is an ordered comma-list of coding tokens. Both ingress paths of
/// the negotiated-gzip feature — the server's request decode (mod_jsonrpc_server)
/// and the client's response decode (jsonrpc_client) — need the SAME split of that
/// combined value into ordered, OWS-trimmed, non-empty tokens. This shared free
/// function is that one implementation (promoted out of the two verbatim per-module
/// copies), sitting beside the Accept-Encoding acceptability primitive
/// (accept_encoding.hpp) in the shared parsers layer both modules already consume.
///
/// Deliberately Content-Encoding-scoped (NOT a generic splitCommaList(delim)) — only
/// content-coding lists need this today; a premature generalization would be unused
/// surface (YAGNI).

namespace iora
{
namespace parsers
{

/// \brief Split an (already combined, RFC 9110 §5.3) Content-Encoding value into
/// ordered, OWS-trimmed coding tokens, skipping empty/whitespace-only elements
/// (RFC 9110 §5.6.1 — a legal consequence of comma-combining, e.g. "gzip,," or
/// ", gzip"). Tokens keep their original case; callers compare case-insensitively
/// (RFC 9110 §8.4.1). Composes the foundation StringUtils::split/trim primitives.
inline std::vector<std::string> splitContentCodings(const std::string &value)
{
  std::vector<std::string> out;
  for (std::string_view tok : iora::core::StringUtils::split(value, ','))
  {
    const std::string_view trimmed = iora::core::StringUtils::trim(tok);
    if (!trimmed.empty())
    {
      out.emplace_back(trimmed);
    }
  }
  return out;
}

/// \brief True iff \p tok is the gzip content coding or its legacy alias x-gzip
/// (RFC 9110 §8.4.1), compared ASCII case-insensitively. The single home for the
/// gzip/x-gzip equivalence used by both content-coding DECODE paths (server request,
/// client response). NOTE: gzipAcceptable (accept_encoding.hpp) intentionally keeps
/// its own self-contained token match — that header does not depend on core/ and its
/// match is fused into the q-value scan; do not reroute it through this helper.
inline bool isGzipContentCoding(std::string_view tok)
{
  return iora::core::StringUtils::iequals(tok, "gzip") ||
         iora::core::StringUtils::iequals(tok, "x-gzip");
}

/// \brief Scrub an untrusted content-coding value for safe inclusion in a diagnostic
/// / exception message that may be logged: keep only printable ASCII, fold any
/// whitespace to a single space, drop other control octets, and bound the length —
/// so a hostile/non-conformant peer's Content-Encoding cannot forge log lines
/// (log-integrity; there is no header sink here). Mirrors the DnsResolver precedent.
inline std::string sanitizeCodingForLog(std::string_view value, std::size_t maxLength = 128)
{
  std::string out;
  const std::size_t n = value.size() < maxLength ? value.size() : maxLength;
  out.reserve(n);
  for (std::size_t i = 0; i < n; ++i)
  {
    const unsigned char c = static_cast<unsigned char>(value[i]);
    if (c >= 32 && c <= 126)
    {
      out.push_back(static_cast<char>(c));
    }
    else if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
    {
      out.push_back(' ');
    }
    // other control octets are dropped
  }
  if (value.size() > maxLength)
  {
    out += "...";
  }
  return out;
}

} // namespace parsers
} // namespace iora
