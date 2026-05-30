// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Logic-less Mustache template engine over iora::parsers::Json.
// See architecture/iora/mustache_engine.json for the authoritative design.
//
// The engine binds directly to iora::parsers::Json (NOT nlohmann) and honors
// that type's sharp edges: const Json& only (non-const operator[] default-
// inserts, MEP-2/CONST-TRAP); bespoke isFalsy() truthiness, never
// Json::operator bool() (MEP-3); sections iterate ARRAYS only (MEP-4); every
// Json access is isX()-gated, const accessors throw (MEP-5); explicit scalar
// formatting via snprintf %g, never operator std::string()/dump() (MEP-6);
// {{var}} escapes via iora::parsers::escapeHtml (MEP-8); render recursion is
// bounded by ParseLimits::depthMax covering BOTH section nesting and partial
// expansion (MEP-7). It depends only on parsers/json.hpp and
// parsers/html_escape.hpp — never web/assets.hpp (MEP-10).

#pragma once

#include <cstddef>
#include <cstdio>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <iora/parsers/html_escape.hpp>
#include <iora/parsers/json.hpp>

namespace iora
{
namespace parsers
{

/// Structural template error: unbalanced/mismatched section, unterminated tag,
/// unknown sigil, partial-not-found, or render-recursion depth exceeded.
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

private:
  // ---- Tokenizer model -----------------------------------------------------

  /// Classification of a flat token produced by the single-pass tokenizer.
  enum class Kind
  {
    Literal,      ///< Verbatim text span
    Variable,     ///< {{name}} escaped interpolation
    Unescaped,    ///< {{{name}}} or {{&name}} unescaped interpolation
    SectionOpen,  ///< {{#name}}
    InvertedOpen, ///< {{^name}}
    SectionClose, ///< {{/name}}
    Partial,      ///< {{>name}}
    Comment       ///< {{!...}} (dropped after standalone processing)
  };

  /// A flat token. NAMES are OWNING std::string so a token vector outlives the
  /// buffer it was tokenized from — load-bearing for partials whose source is a
  /// temporary std::string from the resolver (cpp M-3).
  struct FlatTok
  {
    Kind kind;
    std::string text;   ///< Literal content (Kind::Literal only)
    std::string name;   ///< Trimmed tag name (tag kinds only)
    std::string indent; ///< Captured indent of a standalone partial
  };

  // ---- Parse tree model ----------------------------------------------------

  enum class NodeType
  {
    Literal,
    Variable,
    Unescaped,
    Section,
    Inverted,
    Partial
  };

  struct Node
  {
    NodeType type;
    std::string text;           ///< Literal content OR tag name
    std::string indent;         ///< Standalone partial indent
    std::vector<Node> children; ///< Section / inverted-section body
  };

  // ---- Helpers -------------------------------------------------------------

  /// Maximum render-recursion / section-nesting depth (mirrors json.hpp:90).
  static int depthLimit() { return static_cast<int>(ParseLimits{}.depthMax); }

  /// Static null sentinel returned for any unresolved name (defined empty /
  /// falsy behavior, never an error — MEP-9).
  static const Json& nullSentinel()
  {
    static const Json kNull;
    return kNull;
  }

  /// Trim leading/trailing ASCII whitespace from a tag's inner content.
  static std::string trim(const std::string& s)
  {
    const char* ws = " \t\r\n\v\f";
    const std::size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos)
    {
      return std::string();
    }
    const std::size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
  }

  static bool isStandaloneEligible(Kind k)
  {
    return k == Kind::SectionOpen || k == Kind::InvertedOpen ||
           k == Kind::SectionClose || k == Kind::Partial || k == Kind::Comment;
  }

  /// Bespoke Mustache truthiness (H-2/MEP-3): falsy set is exactly
  /// { null, false, empty array, empty string }. 0 and 0.0 are TRUTHY (L-5).
  /// isX()-gated only; never Json::operator bool(); never an unguarded size()
  /// (H-1: size() throws for scalar kinds).
  static bool isFalsy(const Json& v)
  {
    if (v.isNull())
    {
      return true;
    }
    if (v.isBool())
    {
      return !v.getBool();
    }
    if (v.isArray())
    {
      return v.getArray().empty();
    }
    if (v.isString())
    {
      return v.getString().empty();
    }
    return false; // objects, numbers (incl. 0/0.0), non-empty array/string
  }

  /// Explicit per-alternative scalar formatting (MEP-6/SCALAR-FMT). Never uses
  /// Json::operator std::string()/dump(); double via snprintf %g, never %f and
  /// never std::to_chars<double>.
  static std::string formatScalar(const Json& v)
  {
    if (v.isString())
    {
      return v.getString();
    }
    if (v.isInt())
    {
      return std::to_string(v.getInt());
    }
    if (v.isDouble())
    {
      // buf[32] is provably sufficient for "%g" at default 6-significant-digit
      // precision: the longest output (a negative number in scientific
      // notation, e.g. "-1.23457e+308") is ~14 chars, so snprintf truncation
      // is impossible at this size. Do not shrink this buffer.
      char buf[32];
      std::snprintf(buf, sizeof(buf), "%g", v.getDouble());
      return std::string(buf);
    }
    if (v.isBool())
    {
      return v.getBool() ? "true" : "false";
    }
    return std::string(); // null, array, object in a scalar position
  }

  /// Read-only name / dotted-path resolution (M-2/CONST-TRAP/RD-13). Uses only
  /// isObject() + contains() + the const operator[] — three non-throwing
  /// primitives; never find(), at(), items(), or the non-const operator[].
  /// Returns the static null sentinel for any unresolved path (MEP-9).
  static const Json& resolve(const std::string& name,
                             const std::vector<const Json*>& stack)
  {
    // Implicit iterator: the innermost frame itself.
    if (name == ".")
    {
      return stack.empty() ? nullSentinel() : *stack.back();
    }

    const std::size_t dot = name.find('.');
    const std::string first = (dot == std::string::npos) ? name : name.substr(0, dot);

    // First segment: walk the context stack innermost -> outermost.
    const Json* cur = nullptr;
    for (auto it = stack.rbegin(); it != stack.rend(); ++it)
    {
      const Json* frame = *it;
      if (frame->isObject() && frame->contains(first))
      {
        cur = &((*frame)[first]);
        break;
      }
    }
    if (cur == nullptr)
    {
      return nullSentinel();
    }
    if (dot == std::string::npos)
    {
      return *cur;
    }

    // Subsequent segments descend ONLY from the resolved node (no stack
    // re-walk). A missing tail or a non-object node yields the null sentinel.
    std::size_t pos = dot + 1;
    while (true)
    {
      const std::size_t next = name.find('.', pos);
      const std::string seg =
        (next == std::string::npos) ? name.substr(pos) : name.substr(pos, next - pos);
      if (cur->isObject())
      {
        cur = &((*cur)[seg]); // null sentinel if absent
      }
      else
      {
        return nullSentinel();
      }
      if (next == std::string::npos)
      {
        break;
      }
      pos = next + 1;
    }
    return *cur;
  }

  /// Apply a standalone partial's captured indentation to its SOURCE before
  /// rendering (MEP-7/STANDALONE-LINE, web wH-2/wM-3): prepend the indent at the
  /// start (unless the source begins with a newline) and after every interior
  /// newline that is immediately followed by a non-newline character, but NOT
  /// before an empty line and NOT after a trailing newline. (Matches the
  /// mustache.js indentPartial rule, which skips blank lines so they do not
  /// become trailing-whitespace lines.) Applying to the source — not the
  /// rendered output — ensures newlines injected by interpolated data are not
  /// re-indented.
  static std::string applyIndent(const std::string& src, const std::string& indent)
  {
    if (indent.empty() || src.empty())
    {
      return src;
    }
    std::string out;
    out.reserve(src.size() + indent.size());
    if (src[0] != '\n')
    {
      out += indent; // first line is non-empty
    }
    for (std::size_t i = 0; i < src.size(); ++i)
    {
      const char c = src[i];
      out += c;
      if (c == '\n' && i + 1 < src.size() && src[i + 1] != '\n')
      {
        out += indent; // next line exists and is non-empty
      }
    }
    return out;
  }

  // ---- Tokenizer -----------------------------------------------------------

  /// A raw tag with buffer offsets, used for standalone detection before
  /// literals are materialized.
  struct RawTag
  {
    Kind kind;
    std::string name;
    std::string indent;
    std::size_t start = 0;         ///< Offset of "{{"
    std::size_t end = 0;           ///< Offset just past the closing delimiter
    bool standalone = false;
    std::size_t leftTrimStart = 0; ///< Start of the leading whitespace on the line
    std::size_t rightTrimEnd = 0;  ///< End of the consumed trailing ws + newline
  };

  /// Single forward pass producing the flat token list with standalone-line
  /// stripping and standalone-partial indentation applied (internalModel,
  /// STANDALONE-LINE). Throws MustacheError on an unterminated tag.
  static std::vector<FlatTok> tokenize(std::string_view sv)
  {
    const std::size_t n = sv.size();

    // Pass 1: scan tags, recording buffer offsets.
    std::vector<RawTag> tags;
    std::size_t i = 0;
    while (i < n)
    {
      const std::size_t open = sv.find("{{", i);
      if (open == std::string_view::npos)
      {
        break;
      }
      RawTag tag;
      tag.start = open;
      if (open + 2 < n && sv[open + 2] == '{')
      {
        // Triple-stache {{{ ... }}} — always unescaped interpolation.
        const std::size_t contentStart = open + 3;
        const std::size_t close = sv.find("}}}", contentStart);
        if (close == std::string_view::npos)
        {
          throw MustacheError("unterminated unescaped tag ({{{ without }}})");
        }
        tag.kind = Kind::Unescaped;
        tag.name = trim(std::string(sv.substr(contentStart, close - contentStart)));
        tag.end = close + 3;
      }
      else
      {
        const std::size_t contentStart = open + 2;
        const std::size_t close = sv.find("}}", contentStart);
        if (close == std::string_view::npos)
        {
          throw MustacheError("unterminated tag ({{ without }})");
        }
        const std::string trimmed =
          trim(std::string(sv.substr(contentStart, close - contentStart)));
        if (trimmed.empty())
        {
          tag.kind = Kind::Variable; // {{}} / {{ }} -> empty name -> empty output
          tag.name = std::string();
        }
        else
        {
          switch (trimmed[0])
          {
            case '#':
              tag.kind = Kind::SectionOpen;
              tag.name = trim(trimmed.substr(1));
              break;
            case '^':
              tag.kind = Kind::InvertedOpen;
              tag.name = trim(trimmed.substr(1));
              break;
            case '/':
              tag.kind = Kind::SectionClose;
              tag.name = trim(trimmed.substr(1));
              break;
            case '>':
              tag.kind = Kind::Partial;
              tag.name = trim(trimmed.substr(1));
              break;
            case '!':
              tag.kind = Kind::Comment;
              break;
            case '&':
              tag.kind = Kind::Unescaped;
              tag.name = trim(trimmed.substr(1));
              break;
            case '=':
              // Set-delimiter tags ({{=<% %>=}}) are unsupported in v1
              // (knownLimitations). Reject loudly rather than silently
              // mis-rendering the rest of the template (web L-1).
              throw MustacheError("set-delimiter tags ({{=...=}}) are not "
                                  "supported");
            default:
              tag.kind = Kind::Variable;
              tag.name = trimmed;
              break;
          }
        }
        tag.end = close + 2;
      }
      tags.push_back(std::move(tag));
      i = tags.back().end;
    }

    // Pass 2: standalone detection over the raw buffer (immune to mutation).
    for (RawTag& tag : tags)
    {
      if (!isStandaloneEligible(tag.kind))
      {
        continue;
      }
      // Left: the run between the previous newline (or BOF) and the tag must be
      // whitespace only.
      std::size_t ls = tag.start;
      while (ls > 0 && sv[ls - 1] != '\n')
      {
        --ls;
      }
      bool leftClear = true;
      for (std::size_t k = ls; k < tag.start; ++k)
      {
        if (sv[k] != ' ' && sv[k] != '\t')
        {
          leftClear = false;
          break;
        }
      }
      if (!leftClear)
      {
        continue;
      }
      // Right: optional whitespace then a newline (or EOF). A \r\n is one
      // newline and is consumed in full.
      std::size_t we = tag.end;
      while (we < n && (sv[we] == ' ' || sv[we] == '\t'))
      {
        ++we;
      }
      std::size_t rte;
      if (we == n)
      {
        rte = we; // EOF
      }
      else if (sv[we] == '\n')
      {
        rte = we + 1;
      }
      else if (sv[we] == '\r' && we + 1 < n && sv[we + 1] == '\n')
      {
        rte = we + 2;
      }
      else
      {
        continue; // other content on the line -> not standalone
      }
      tag.standalone = true;
      tag.leftTrimStart = ls;
      tag.rightTrimEnd = rte;
      if (tag.kind == Kind::Partial)
      {
        tag.indent = std::string(sv.substr(ls, tag.start - ls));
      }
    }

    // Pass 3: materialize literals from the gaps (with standalone trims) and
    // emit tag tokens. Comments are dropped (their standalone trim is already
    // folded into the surrounding gaps).
    std::vector<FlatTok> out;
    auto emitLiteral = [&](std::size_t a, std::size_t b)
    {
      if (b > a)
      {
        FlatTok lit;
        lit.kind = Kind::Literal;
        lit.text = std::string(sv.substr(a, b - a));
        out.push_back(std::move(lit));
      }
    };
    std::size_t boundary = 0;
    for (RawTag& tag : tags)
    {
      const std::size_t gapEnd = tag.standalone ? tag.leftTrimStart : tag.start;
      emitLiteral(boundary, gapEnd);
      if (tag.kind != Kind::Comment)
      {
        FlatTok tok;
        tok.kind = tag.kind;
        tok.name = std::move(tag.name);
        tok.indent = std::move(tag.indent);
        out.push_back(std::move(tok));
      }
      boundary = tag.standalone ? tag.rightTrimEnd : tag.end;
    }
    emitLiteral(boundary, n);
    return out;
  }

  // ---- Parser (structural validation) --------------------------------------

  /// Build the parse tree from the flat token list, validating section
  /// balance (task-1.4). @p sectionDepth bounds static nesting against the same
  /// depthLimit() used at render time. Throws MustacheError on an unbalanced,
  /// stray, or mismatched section close, or excessive nesting.
  static std::vector<Node> buildTree(const std::vector<FlatTok>& toks, std::size_t& i,
                                     int sectionDepth, bool inSection,
                                     const std::string& openName)
  {
    // Parse-time guard: first line of defense against a pathologically deep
    // statically-nested template exhausting the C++ stack. The render-time
    // guard in renderNodes() bounds TOTAL recursion (sections + partial
    // expansion); together they satisfy MEP-7/RENDER-DEPTH. Both throw
    // MustacheError, which is all callers/tests depend on.
    if (sectionDepth > depthLimit())
    {
      throw MustacheError("section nesting too deep (limit " +
                          std::to_string(depthLimit()) + ")");
    }
    std::vector<Node> out;
    while (i < toks.size())
    {
      const FlatTok& t = toks[i];
      switch (t.kind)
      {
        case Kind::Literal:
          out.push_back(Node{NodeType::Literal, t.text, std::string(), {}});
          ++i;
          break;
        case Kind::Variable:
          out.push_back(Node{NodeType::Variable, t.name, std::string(), {}});
          ++i;
          break;
        case Kind::Unescaped:
          out.push_back(Node{NodeType::Unescaped, t.name, std::string(), {}});
          ++i;
          break;
        case Kind::Partial:
          out.push_back(Node{NodeType::Partial, t.name, t.indent, {}});
          ++i;
          break;
        case Kind::Comment:
          ++i; // dropped during tokenization; defensive
          break;
        case Kind::SectionOpen:
        case Kind::InvertedOpen:
        {
          const bool inverted = (t.kind == Kind::InvertedOpen);
          const std::string nm = t.name;
          ++i; // consume the open tag
          Node sec;
          sec.type = inverted ? NodeType::Inverted : NodeType::Section;
          sec.text = nm;
          sec.children = buildTree(toks, i, sectionDepth + 1, true, nm);
          out.push_back(std::move(sec));
          break;
        }
        case Kind::SectionClose:
        {
          if (!inSection)
          {
            throw MustacheError("unexpected {{/" + t.name + "}} (no open section)");
          }
          if (t.name != openName)
          {
            throw MustacheError("mismatched section close: {{#" + openName +
                                "}} closed by {{/" + t.name + "}}");
          }
          ++i; // consume the close tag
          return out;
        }
      }
    }
    if (inSection)
    {
      throw MustacheError("unclosed section {{#" + openName + "}}");
    }
    return out;
  }

  // ---- Renderer ------------------------------------------------------------

  /// Recursive walk over the parse tree against the shared, live context stack.
  /// @p depth bounds TOTAL render recursion — section descent AND partial
  /// expansion (MEP-7/RENDER-DEPTH) — and is checked on entry.
  static void renderNodes(const std::vector<Node>& nodes,
                          std::vector<const Json*>& stack,
                          const PartialResolver& partials, int depth,
                          std::string& out)
  {
    if (depth > depthLimit())
    {
      throw MustacheError("render recursion too deep (limit " +
                          std::to_string(depthLimit()) + ")");
    }
    for (const Node& nd : nodes)
    {
      switch (nd.type)
      {
        case NodeType::Literal:
          out += nd.text;
          break;
        case NodeType::Variable:
          out += escapeHtml(formatScalar(resolve(nd.text, stack)));
          break;
        case NodeType::Unescaped:
          out += formatScalar(resolve(nd.text, stack));
          break;
        case NodeType::Section:
        {
          const Json& v = resolve(nd.text, stack);
          if (isFalsy(v))
          {
            break;
          }
          if (v.isArray())
          {
            // Non-empty array (empty arrays are falsy): body once per element.
            const Json::Array& arr = v.getArray();
            for (const Json& e : arr)
            {
              stack.push_back(&e);
              renderNodes(nd.children, stack, partials, depth + 1, out);
              stack.pop_back();
            }
          }
          else
          {
            // Object or non-falsy scalar: body exactly once with v pushed.
            stack.push_back(&v);
            renderNodes(nd.children, stack, partials, depth + 1, out);
            stack.pop_back();
          }
          break;
        }
        case NodeType::Inverted:
        {
          const Json& v = resolve(nd.text, stack);
          if (isFalsy(v))
          {
            // Body once; never pushes a context.
            renderNodes(nd.children, stack, partials, depth + 1, out);
          }
          break;
        }
        case NodeType::Partial:
        {
          // Lazy: the resolver is invoked only when the token is reached.
          if (!partials)
          {
            throw MustacheError("no partial resolver provided for {{>" + nd.text + "}}");
          }
          std::optional<std::string> src = partials(nd.text);
          if (!src)
          {
            throw MustacheError("partial not found: " + nd.text);
          }
          // Hold the (possibly indented) source in a local that outlives the
          // recursive call. Standalone-partial indentation is applied to the
          // SOURCE before tokenizing (web wH-2/wM-3).
          const std::string source =
            nd.indent.empty() ? std::move(*src) : applyIndent(*src, nd.indent);
          const std::vector<FlatTok> flat = tokenize(source);
          std::size_t idx = 0;
          const std::vector<Node> tree =
            buildTree(flat, idx, 0, false, std::string());
          // Shared live context stack; depth + 1 bounds partial cycles.
          renderNodes(tree, stack, partials, depth + 1, out);
          break;
        }
      }
    }
  }
};

inline std::string Mustache::render(std::string_view tmpl, const Json& data,
                                    const PartialResolver& partials)
{
  const std::vector<FlatTok> flat = tokenize(tmpl);
  std::size_t idx = 0;
  const std::vector<Node> tree = buildTree(flat, idx, 0, false, std::string());
  std::string out;
  out.reserve(tmpl.size());
  std::vector<const Json*> stack;
  stack.push_back(&data);
  renderNodes(tree, stack, partials, 0, out);
  return out;
}

} // namespace parsers
} // namespace iora
