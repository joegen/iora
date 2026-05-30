// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Logic-less Mustache template engine over iora::parsers::Json.
// See architecture/iora/mustache_engine.json for the authoritative design.
//
// SKELETON (step 1 of the implementation workflow): public API only, with a
// stub render() body. The full engine is implemented in step 2.

#pragma once

#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

#include <iora/parsers/html_escape.hpp>
#include <iora/parsers/json.hpp>

namespace iora
{
namespace parsers
{

/// Structural template error: unbalanced/mismatched section, unterminated tag,
/// unknown sigil, partial-not-found, or partial-recursion depth exceeded.
/// Missing values are NOT errors (MEP-9).
class MustacheError : public std::runtime_error
{
  using std::runtime_error::runtime_error;
};

/// Maps a partial name (from {{>name}}) to its template source. Returns
/// std::nullopt for an unknown partial (=> MustacheError when reached).
/// Resolution is LAZY (RD-13): invoked only when a {{>name}} token is reached.
using PartialResolver =
  std::function<std::optional<std::string>(std::string_view name)>;

/// Logic-less Mustache engine. Stateless and reentrant.
class Mustache
{
public:
  /// Render @p tmpl against @p data, resolving partials via @p partials.
  /// Throws MustacheError on a structural template error; never throws
  /// std::bad_variant_access or Json::type_error (all access is isX()-gated).
  static std::string render(std::string_view tmpl, const Json& data,
                            const PartialResolver& partials = {});
};

inline std::string Mustache::render(std::string_view tmpl, const Json& data,
                                    const PartialResolver& partials)
{
  // STUB — replaced by the full implementation in step 2.
  (void)tmpl;
  (void)data;
  (void)partials;
  return std::string();
}

} // namespace parsers
} // namespace iora
