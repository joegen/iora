#pragma once
/// \file xml.hpp
/// \brief Single-header, non-validating XML 1.0 parser for C++17 with pull, SAX, and optional DOM
/// APIs.
///
/// Design goals:
///  - Header-only, zero external deps
///  - Non-validating (no DTD/XSD); safe-by-default (no external entity expansion)
///  - Efficient pull-token API; optional SAX callbacks; optional lightweight DOM builder
///  - UTF-8 primary encoding; predefined entities + numeric char refs
///  - Iora style: 2-space indent, Allman braces, camelCase, PascalCase types, _member prefix, no
///  using-namespace in headers
///
/// Example (pull API):
/// \code
/// iora::parsers::xml::Parser parser("<root a=\"1\">hi &amp; bye</root>");
/// while (parser.next())
/// {
///   const auto &tok = parser.current();
///   if (tok.kind == iora::parsers::xml::TokenKind::StartElement)
///   {
///     // ...
///   }
/// }
/// if (parser.error()) { /* handle */ }
/// \endcode
///
/// SPDX-License-Identifier: MPL-2.0

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifndef IORA_XML_ENABLE_SAX
#define IORA_XML_ENABLE_SAX 1
#endif
#ifndef IORA_XML_ENABLE_DOM
#define IORA_XML_ENABLE_DOM 1
#endif
#ifndef IORA_XML_THROW_ON_ERROR
#define IORA_XML_THROW_ON_ERROR 0
#endif

namespace iora
{
namespace parsers
{
namespace xml
{
/// \brief Token kinds produced by the pull parser.
enum class TokenKind
{
  Invalid,
  Eof,
  XmlDecl,
  Doctype,
  StartElement,
  EndElement,
  EmptyElement,
  Text,
  CData,
  Comment,
  ProcessingInstruction
};

/// \brief Error information for parse failures.
struct Error
{
  std::size_t offset{0};
  std::size_t line{1};
  std::size_t column{1};
  std::string message;
};

/// \brief Parser configuration options and safety limits.
struct Options
{
  bool permissive{false};              ///< Best-effort recovery for minor issues
  bool namespaceProcessing{true};      ///< Expose prefix/localName split; no URI resolution
  std::size_t maxDepth{256};           ///< Max element nesting depth
  std::size_t maxAttrsPerElement{256}; ///< Max attributes per element
  std::size_t maxNameLength{1024};     ///< Max length of element or attribute names
  std::size_t maxTextSpan{1u << 20};   ///< Max contiguous text span in bytes (1 MiB)
  std::size_t maxTotalTokens{0};       ///< 0=unbounded; otherwise cap total tokens
};

/// \brief Attribute view (name/value) for tokens. Values are source slices; use decode*() for
/// entity-decoded strings.
struct Attribute
{
  std::string_view name;
  std::string_view value;
};

/// \brief Token produced by the pull parser.
struct Token
{
  TokenKind kind{TokenKind::Invalid};
  std::string_view name;             ///< For elements/PI/decl/doctype: raw name or target
  std::string_view text;             ///< For Text/Comment/CData/PI: raw text slice
  std::vector<Attribute> attributes; ///< For StartElement/EmptyElement and XmlDecl
  bool selfClosing{false};           ///< For EmptyElement convenience
  std::size_t depth{0};              ///< Element depth at this token (root element has depth 1)
  std::size_t offset{0};             ///< Byte offset of token start
  std::size_t line{1};
  std::size_t column{1};

  /// \brief Returns the localName and prefix split from name (no URI resolution).
  std::pair<std::string_view, std::string_view> splitQName() const
  {
    std::size_t pos = name.find(':');
    if (pos == std::string_view::npos)
    {
      return {std::string_view{}, name};
    }
    return {name.substr(0, pos), name.substr(pos + 1)};
  }
};

/// \brief Minimal monotonic arena for optional DOM allocations.
class MonotonicArena
{
public:
  MonotonicArena() = default;

  ~MonotonicArena()
  {
    for (auto &b : _blocks)
    {
      delete[] b.ptr;
    }
  }

  void *allocate(std::size_t n)
  {
    n = (n + alignof(std::max_align_t) - 1) & ~(alignof(std::max_align_t) - 1);
    if (_blocks.empty() || _blocks.back().used + n > _blocks.back().size)
    {
      std::size_t sz = std::max<std::size_t>(n, _nextGrowth);
      Block b;
      b.ptr = new char[sz];
      b.size = sz;
      b.used = 0;
      _blocks.push_back(b);
      if (_nextGrowth < (1u << 20))
      {
        _nextGrowth *= 2; // grow up to 1 MiB blocks
      }
    }
    Block &blk = _blocks.back();
    void *p = blk.ptr + blk.used;
    blk.used += n;
    return p;
  }

  template <class T> T *make()
  {
    void *p = allocate(sizeof(T));
    return new (p) T();
  }

  template <class T> T *makeArray(std::size_t count)
  {
    void *p = allocate(sizeof(T) * count);
    return reinterpret_cast<T *>(p);
  }

private:
  struct Block
  {
    char *ptr{nullptr};
    std::size_t size{0};
    std::size_t used{0};
  };

  std::vector<Block> _blocks;
  std::size_t _nextGrowth{4096};
};

/// \brief Parser: non-validating XML tokenizer with pull API.
class Parser
{
public:
  /// \brief Construct a parser over a contiguous UTF-8 buffer.
  Parser(std::string_view input, const Options &opt = Options{}) : _input(input), _opt(opt)
  {
    _cur = 0;
    _line = 1;
    _col = 1;
    _depth = 0;
    _token = Token{};
    _producedTokens = 0;
    _elementStack.clear();
  }

  /// \brief Returns the current token after a successful next().
  const Token &current() const { return _token; }

  /// \brief Returns last error pointer if any (nullptr if none).
  const Error *error() const { return _hasError ? &_error : nullptr; }

  /// \brief Advance to the next token. Returns false on error or when EOF has been emitted.
  bool next()
  {
    if (_hasError)
    {
      return false;
    }
    if (_emittedEof)
    {
      return false;
    }
    if (_opt.maxTotalTokens != 0 && _producedTokens >= _opt.maxTotalTokens)
    {
      return fail("token limit exceeded");
    }

    skipWhitespaceOutsideText();
    if (eof())
    {
      emitEof();
      return false;
    }

    std::size_t startOffset = _cur;
    std::size_t startLine = _line;
    std::size_t startCol = _col;

    char c = peek();
    if (c == '<')
    {
      // Tag, comment, CDATA, PI, doctype
      advance();
      if (eof())
      {
        return fail("unexpected end after '<'");
      }
      char n = peek();
      if (n == '?')
      {
        advance();
        return readProcessingInstruction(startOffset, startLine, startCol);
      }
      else if (n == '!')
      {
        advance();
        if (matchString("--"))
        {
          return readComment(startOffset, startLine, startCol);
        }
        if (matchString("[CDATA["))
        {
          return readCData(startOffset, startLine, startCol);
        }
        if (matchWordCaseInsensitive("DOCTYPE"))
        {
          return readDoctype(startOffset, startLine, startCol);
        }
        return fail("unsupported markup declaration");
      }
      else if (n == '/')
      {
        advance();
        return readEndTag(startOffset, startLine, startCol);
      }
      else
      {
        return readStartOrEmptyTag(startOffset, startLine, startCol);
      }
    }
    else
    {
      return readText(startOffset, startLine, startCol);
    }
  }

  /// \brief Decode predefined entities and numeric char refs in a slice.
  static bool decodeEntities(std::string_view in, std::string &out, Error *err = nullptr)
  {
    out.clear();
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size();)
    {
      char ch = in[i];
      if (ch != '&')
      {
        out.push_back(ch);
        ++i;
        continue;
      }
      // Entity
      std::size_t semi = in.find(';', i + 1);
      if (semi == std::string_view::npos)
      {
        if (err)
        {
          *err = {i, 0, 0, "unterminated entity"};
        }
        return false;
      }
      std::string_view ent = in.substr(i + 1, semi - (i + 1));
      if (ent == "lt")
        out.push_back('<');
      else if (ent == "gt")
        out.push_back('>');
      else if (ent == "amp")
        out.push_back('&');
      else if (ent == "apos")
        out.push_back('\'');
      else if (ent == "quot")
        out.push_back('"');
      else if (!ent.empty() && ent[0] == '#')
      {
        bool ok = appendCharRef(ent, out);
        if (!ok)
        {
          if (err)
          {
            *err = {i, 0, 0, "invalid character reference"};
          }
          return false;
        }
      }
      else
      {
        if (err)
        {
          *err = {i, 0, 0, "unknown entity"};
        }
        return false; // external entities unsupported by design
      }
      i = semi + 1;
    }
    return true;
  }

private:
  // ===== Low-level cursor helpers =====
  bool eof() const { return _cur >= _input.size(); }

  char peek() const { return _input[_cur]; }

  char get()
  {
    char ch = _input[_cur++];
    if (ch == '\n')
    {
      ++_line;
      _col = 1;
    }
    else
    {
      ++_col;
    }
    return ch;
  }

  void advance() { (void)get(); }

  bool isNameStart(char ch) const
  {
    return (ch == ':' || ch == '_' || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'));
  }

  bool isNameChar(char ch) const
  {
    return isNameStart(ch) || (ch == '-' || ch == '.' || (ch >= '0' && ch <= '9'));
  }

  void skipSpaces()
  {
    while (!eof())
    {
      char ch = peek();
      if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
      {
        advance();
      }
      else
      {
        break;
      }
    }
  }

  void skipWhitespaceOutsideText()
  {
    // Only skip if next thing is markup or beginning; do not consume text spaces.
    while (!eof())
    {
      char ch = peek();
      if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
      {
        advance();
        continue;
      }
      if (ch == '<')
      {
        // stop; next() will handle
        return;
      }
      // Non-space text ahead; let readText handle
      return;
    }
  }

  bool matchString(const char *s)
  {
    std::size_t i = 0;
    while (s[i] != '\0')
    {
      if (_cur + i >= _input.size())
      {
        return false;
      }
      if (_input[_cur + i] != s[i])
      {
        return false;
      }
      ++i;
    }
    // advance
    for (std::size_t j = 0; j < i; ++j)
    {
      advance();
    }
    return true;
  }

  bool matchWordCaseInsensitive(const char *s)
  {
    // Matches a word ignoring ASCII case, requires a following whitespace or '>' or '['
    std::size_t i = 0;
    std::size_t pos = _cur;
    while (s[i] != '\0')
    {
      if (pos + i >= _input.size())
      {
        return false;
      }
      char a = _input[pos + i];
      char b = s[i];
      if (a >= 'A' && a <= 'Z')
      {
        a = static_cast<char>(a - 'A' + 'a');
      }
      if (b >= 'A' && b <= 'Z')
      {
        b = static_cast<char>(b - 'A' + 'a');
      }
      if (a != b)
      {
        return false;
      }
      ++i;
    }
    // Check word boundary
    char next = (pos + i < _input.size() ? _input[pos + i] : '\0');
    if (!(next == ' ' || next == '\t' || next == '\r' || next == '\n' || next == '>' ||
          next == '['))
    {
      return false;
    }
    // advance
    for (std::size_t j = 0; j < i; ++j)
    {
      advance();
    }
    return true;
  }

  std::string_view readName()
  {
    std::size_t start = _cur;
    if (eof() || !isNameStart(peek()))
    {
      return std::string_view{};
    }
    advance();
    while (!eof() && isNameChar(peek()))
    {
      advance();
    }
    std::size_t len = _cur - start;
    if (len > _opt.maxNameLength)
    {
      fail("name too long");
      return std::string_view{};
    }
    return _input.substr(start, len);
  }

  bool readUntil(std::string_view endSeq, std::size_t &startOut, std::size_t &lenOut)
  {
    // naive search; acceptable for typical sizes
    std::size_t pos = _cur;
    while (true)
    {
      if (pos >= _input.size())
      {
        return false;
      }
      if (_input.compare(pos, endSeq.size(), endSeq) == 0)
      {
        startOut = _cur;
        lenOut = pos - _cur;
        // advance cursor to position after endSeq
        while (_cur < pos + endSeq.size())
        {
          advance();
        }
        return true;
      }
      // advance one char
      char ch = _input[pos++];
      if (ch == '\n')
      {
        // Maintain line/col if we step via get(); we are peeking here, so adjust counters on next
        // get() calls only.
      }
    }
  }

  bool readQuotedValue(std::string_view &out)
  {
    if (eof())
    {
      return fail("expected quote");
    }
    char quote = peek();
    if (quote != '"' && quote != '\'')
    {
      return fail("expected '\"' or '\'' for attribute value");
    }
    advance();
    std::size_t start = _cur;
    while (!eof() && peek() != quote)
    {
      advance();
    }
    if (eof())
    {
      return fail("unterminated attribute value");
    }
    std::size_t end = _cur;
    advance(); // consume closing quote
    out = _input.substr(start, end - start);
    if (out.size() > _opt.maxTextSpan)
    {
      return fail("attribute value too long");
    }
    return true;
  }

  bool readAttributes(std::vector<Attribute> &attrs)
  {
    attrs.clear();
    attrs.reserve(16); // Pre-allocate space for attributes to avoid reallocation issues
    while (true)
    {
      skipSpaces();
      if (eof())
      {
        return fail("unexpected end in attributes");
      }
      char ch = peek();
      if (ch == '/' || ch == '>')
      {
        return true; // done
      }
      std::string_view name = readName();
      if (name.empty())
      {
        return fail("invalid attribute name");
      }
      skipSpaces();
      if (eof() || peek() != '=')
      {
        return fail("expected '=' after attribute name");
      }
      advance();
      skipSpaces();
      std::string_view value;
      if (!readQuotedValue(value))
      {
        return false;
      }
      attrs.push_back(Attribute{name, value});
      if (attrs.size() > _opt.maxAttrsPerElement)
      {
        return fail("too many attributes");
      }
    }
  }

  bool readProcessingInstruction(std::size_t startOffset, std::size_t startLine,
                                 std::size_t startCol)
  {
    std::string_view target = readName();
    if (target.empty())
    {
      return fail("invalid PI target");
    }
    // Read until '?>'
    // Consume optional whitespace after target
    std::size_t contentStart = _cur;
    // Find '?>'
    std::size_t pos = _input.find("?>", _cur);
    if (pos == std::string::npos)
    {
      return fail("unterminated processing instruction");
    }
    std::string_view content = _input.substr(contentStart, pos - contentStart);
    // Advance cursor to after '?>'
    while (_cur < pos + 2)
    {
      advance();
    }

    _token = Token{};
    _token.kind = TokenKind::ProcessingInstruction;
    _token.name = target;
    _token.text = content;
    _token.depth = _depth;
    _token.offset = startOffset;
    _token.line = startLine;
    _token.column = startCol;
    return produced();
  }

  bool readComment(std::size_t startOffset, std::size_t startLine, std::size_t startCol)
  {
    // Expect until '-->'
    std::size_t start, len;
    if (!readUntil("-->", start, len))
    {
      return fail("unterminated comment");
    }
    _token = Token{};
    _token.kind = TokenKind::Comment;
    _token.text = _input.substr(start, len);
    _token.depth = _depth;
    _token.offset = startOffset;
    _token.line = startLine;
    _token.column = startCol;
    return produced();
  }

  bool readCData(std::size_t startOffset, std::size_t startLine, std::size_t startCol)
  {
    std::size_t start, len;
    if (!readUntil("]]>", start, len))
    {
      return fail("unterminated CDATA");
    }
    _token = Token{};
    _token.kind = TokenKind::CData;
    _token.text = _input.substr(start, len);
    _token.depth = _depth;
    _token.offset = startOffset;
    _token.line = startLine;
    _token.column = startCol;
    return produced();
  }

  bool readDoctype(std::size_t startOffset, std::size_t startLine, std::size_t startCol)
  {
    // Tokenize the DOCTYPE up to the next '>' (naive; internal subset allowed within [])
    std::size_t pos = _cur;
    int bracket = 0;
    while (pos < _input.size())
    {
      char ch = _input[pos];
      if (ch == '[')
      {
        ++bracket;
      }
      else if (ch == ']')
      {
        if (bracket > 0)
        {
          --bracket;
        }
      }
      else if (ch == '>' && bracket == 0)
      {
        break;
      }
      ++pos;
    }
    if (pos >= _input.size())
    {
      return fail("unterminated doctype");
    }
    std::string_view nameAndIds = _input.substr(_cur, pos - _cur);
    while (_cur <= pos)
    {
      advance();
    }

    _token = Token{};
    _token.kind = TokenKind::Doctype;
    _token.text = nameAndIds;
    _token.depth = _depth;
    _token.offset = startOffset;
    _token.line = startLine;
    _token.column = startCol;
    return produced();
  }

  bool readEndTag(std::size_t startOffset, std::size_t startLine, std::size_t startCol)
  {
    std::string_view name = readName();
    if (name.empty())
    {
      return fail("invalid end tag name");
    }
    skipSpaces();
    if (eof() || peek() != '>')
    {
      return fail("expected '>' after end tag name");
    }
    advance();

    // Validate tag balance
    if (_elementStack.empty())
    {
      return fail("end tag without matching start tag");
    }

    // Check if the closing tag matches the most recent opening tag
    if (_elementStack.back() != name)
    {
      std::string msg = "mismatched end tag - expected </" + _elementStack.back() + "> but got </" +
                        std::string(name) + ">";
      return fail(msg.c_str());
    }

    _elementStack.pop_back();
    --_depth;

    _token = Token{};
    _token.kind = TokenKind::EndElement;
    _token.name = name;
    _token.depth = _depth + 1; // depth at this token corresponds to the element being closed
    _token.offset = startOffset;
    _token.line = startLine;
    _token.column = startCol;
    return produced();
  }

  bool readStartOrEmptyTag(std::size_t startOffset, std::size_t startLine, std::size_t startCol)
  {
    std::string_view name = readName();
    if (name.empty())
    {
      return fail("invalid start tag name");
    }
    Token tok;
    tok.kind = TokenKind::StartElement;
    tok.name = name;
    tok.offset = startOffset;
    tok.line = startLine;
    tok.column = startCol;

    if (!readAttributes(tok.attributes))
    {
      return false;
    }

    bool empty = false;
    if (peek() == '/')
    {
      empty = true;
      advance();
    }
    if (eof() || peek() != '>')
    {
      return fail("expected '>' to end start tag");
    }
    advance();

    if (_depth + 1 > _opt.maxDepth)
    {
      return fail("maximum element depth exceeded");
    }

    ++_depth;
    tok.depth = _depth;

    if (empty)
    {
      // Emit EmptyElement token
      tok.kind = TokenKind::EmptyElement;
      tok.selfClosing = true;
      _token = std::move(tok);
      // Depth returns to previous because it's empty
      --_depth;
      // Don't push to stack since it's self-closing
      return produced();
    }
    else
    {
      // Push element name to stack for validation
      _elementStack.push_back(std::string(name));
      _token = std::move(tok);
      return produced();
    }
  }

  bool readText(std::size_t startOffset, std::size_t startLine, std::size_t startCol)
  {
    std::size_t start = _cur;
    while (!eof() && peek() != '<')
    {
      // Limit contiguous span
      if ((_cur - start) >= _opt.maxTextSpan)
      {
        return fail("text span too large");
      }
      advance();
    }
    std::string_view sv = _input.substr(start, _cur - start);
    if (sv.empty())
    {
      // Should not happen; caller guards with '<' check
      return next();
    }
    _token = Token{};
    _token.kind = TokenKind::Text;
    _token.text = sv;
    _token.depth = _depth;
    _token.offset = startOffset;
    _token.line = startLine;
    _token.column = startCol;
    return produced();
  }

  void emitEof()
  {
    // Check for unclosed elements
    if (!_elementStack.empty())
    {
      std::string unclosed = "unclosed elements at end of document: ";
      for (const auto &elem : _elementStack)
      {
        unclosed += "<" + elem + "> ";
      }
      fail(unclosed.c_str());
      return;
    }
    _token = Token{};
    _token.kind = TokenKind::Eof;
    _token.depth = _depth;
    _token.offset = _cur;
    _token.line = _line;
    _token.column = _col;
    _emittedEof = true;
  }

  bool produced()
  {
    ++_producedTokens;
    return true;
  }

  bool fail(const char *msg)
  {
    _hasError = true;
    _error.offset = _cur;
    _error.line = _line;
    _error.column = _col;
    _error.message = msg;
#if IORA_XML_THROW_ON_ERROR
    throw std::runtime_error(_error.message);
#else
    (void)msg;
#endif
    return false;
  }

  // Append a numeric char ref (e.g. "#10" or "#x1F4A9") to out as UTF-8.
  static bool appendCharRef(std::string_view entBody, std::string &out)
  {
    // entBody starts after '#'
    if (entBody.size() < 2)
    {
      return false;
    }
    uint32_t code = 0;
    if (entBody[1] == 'x' || entBody[1] == 'X')
    {
      // hex
      for (std::size_t i = 2; i < entBody.size(); ++i)
      {
        char c = entBody[i];
        uint32_t v = 0;
        if (c >= '0' && c <= '9')
        {
          v = static_cast<uint32_t>(c - '0');
        }
        else if (c >= 'a' && c <= 'f')
        {
          v = static_cast<uint32_t>(c - 'a' + 10);
        }
        else if (c >= 'A' && c <= 'F')
        {
          v = static_cast<uint32_t>(c - 'A' + 10);
        }
        else
        {
          return false;
        }
        code = (code << 4) | v;
      }
    }
    else
    {
      // decimal
      for (std::size_t i = 1; i < entBody.size(); ++i)
      {
        char c = entBody[i];
        if (c < '0' || c > '9')
        {
          return false;
        }
        code = code * 10u + static_cast<uint32_t>(c - '0');
      }
    }
    if (!encodeUtf8(code, out))
    {
      return false;
    }
    return true;
  }

  static bool encodeUtf8(uint32_t cp, std::string &out)
  {
    if (cp <= 0x7Fu)
    {
      out.push_back(static_cast<char>(cp));
    }
    else if (cp <= 0x7FFu)
    {
      out.push_back(static_cast<char>(0xC0u | ((cp >> 6) & 0x1Fu)));
      out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    }
    else if (cp <= 0xFFFFu)
    {
      // Exclude UTF-16 surrogate halves
      if (cp >= 0xD800u && cp <= 0xDFFFu)
      {
        return false;
      }
      out.push_back(static_cast<char>(0xE0u | ((cp >> 12) & 0x0Fu)));
      out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
      out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    }
    else if (cp <= 0x10FFFFu)
    {
      out.push_back(static_cast<char>(0xF0u | ((cp >> 18) & 0x07u)));
      out.push_back(static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu)));
      out.push_back(static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu)));
      out.push_back(static_cast<char>(0x80u | (cp & 0x3Fu)));
    }
    else
    {
      return false;
    }
    return true;
  }

private:
  std::string_view _input;
  Options _opt{};

  std::size_t _cur{0};
  std::size_t _line{1};
  std::size_t _col{1};
  std::size_t _depth{0};

  Token _token{};

  bool _hasError{false};
  Error _error{};
  bool _emittedEof{false};
  std::size_t _producedTokens{0};
  std::vector<std::string> _elementStack{}; // Track open element names for validation
};

#if IORA_XML_ENABLE_SAX
/// \brief SAX-style callbacks (std::function). Register any subset; unregistered ones are skipped.
struct SaxCallbacks
{
  std::function<void(const Token &)>
    onXmlDecl; ///< kind=XmlDecl; attributes contain name/value pairs
  std::function<void(const Token &)> onDoctype;      ///< kind=Doctype; text contains content
  std::function<void(const Token &)> onStartElement; ///< kind=StartElement; attributes available
  std::function<void(const Token &)> onEndElement;   ///< kind=EndElement
  std::function<void(const Token &)> onEmptyElement; ///< kind=EmptyElement; attributes available
  std::function<void(const Token &)> onText;    ///< kind=Text; use Parser::decodeEntities if needed
  std::function<void(const Token &)> onCData;   ///< kind=CData
  std::function<void(const Token &)> onComment; ///< kind=Comment
  std::function<void(const Token &)> onPI;      ///< kind=ProcessingInstruction
};

/// \brief Run the parser and dispatch SAX callbacks.
inline bool runSax(Parser &parser, const SaxCallbacks &cb)
{
  while (parser.next())
  {
    const Token &t = parser.current();
    switch (t.kind)
    {
    case TokenKind::XmlDecl:
      if (cb.onXmlDecl)
      {
        cb.onXmlDecl(t);
      }
      break;
    case TokenKind::Doctype:
      if (cb.onDoctype)
      {
        cb.onDoctype(t);
      }
      break;
    case TokenKind::StartElement:
      if (cb.onStartElement)
      {
        cb.onStartElement(t);
      }
      break;
    case TokenKind::EndElement:
      if (cb.onEndElement)
      {
        cb.onEndElement(t);
      }
      break;
    case TokenKind::EmptyElement:
      if (cb.onEmptyElement)
      {
        cb.onEmptyElement(t);
      }
      break;
    case TokenKind::Text:
      if (cb.onText)
      {
        cb.onText(t);
      }
      break;
    case TokenKind::CData:
      if (cb.onCData)
      {
        cb.onCData(t);
      }
      break;
    case TokenKind::Comment:
      if (cb.onComment)
      {
        cb.onComment(t);
      }
      break;
    case TokenKind::ProcessingInstruction:
      if (cb.onPI)
      {
        cb.onPI(t);
      }
      break;
    case TokenKind::Eof:
    case TokenKind::Invalid:
    default:
      break;
    }
  }
  return parser.error() == nullptr;
}
#endif // IORA_XML_ENABLE_SAX

#if IORA_XML_ENABLE_DOM
/// \brief DOM node kinds built by DomBuilder.
enum class NodeType
{
  Document,
  Element,
  Text,
  CData,
  Comment,
  ProcessingInstruction
};

/// \brief DOM node (lightweight, immutable tree once built).
class Node
{
public:
  NodeType type{NodeType::Element};
  std::string name;  ///< Element/PI name; empty for text/comment/cdata
  std::string value; ///< Text content for Text/CData/Comment/PI; empty for Element/Document

  struct Attr
  {
    std::string name;
    std::string value;
  };

  std::vector<Attr> attributes;                ///< Attributes for Element
  std::vector<std::unique_ptr<Node>> children; ///< Children for Element/Document

  /// \brief Find first direct child element by name; returns nullptr if none.
  const Node *childByName(std::string_view n) const
  {
    for (const auto &c : children)
    {
      if (c->type == NodeType::Element && std::string_view(c->name) == n)
      {
        return c.get();
      }
    }
    return nullptr;
  }

  /// \brief Find attribute by name; returns empty string_view if not found.
  std::string_view getAttribute(std::string_view attrName) const
  {
    for (const auto &attr : attributes)
    {
      if (std::string_view(attr.name) == attrName)
      {
        return attr.value;
      }
    }
    return std::string_view{};
  }

  /// \brief Get text content of all child text nodes concatenated.
  std::string getTextContent() const
  {
    std::string result;
    for (const auto &child : children)
    {
      if (child->type == NodeType::Text || child->type == NodeType::CData)
      {
        result += child->value;
      }
    }
    return result;
  }
};

/// \brief Build a DOM tree from a pull parser.
class DomBuilder
{
public:
  /// \brief Build and return a unique_ptr to the Document node (root).
  static std::unique_ptr<Node> build(Parser &parser, Error *errOut = nullptr)
  {
    std::unique_ptr<Node> doc = std::make_unique<Node>();
    doc->type = NodeType::Document;

    std::vector<Node *> stack;
    stack.push_back(doc.get());

    while (parser.next())
    {
      const Token &t = parser.current();
      switch (t.kind)
      {
      case TokenKind::StartElement:
      {
        auto elem = std::make_unique<Node>();
        elem->type = NodeType::Element;
        elem->name = std::string(t.name);
        elem->attributes.reserve(t.attributes.size());
        for (const auto &a : t.attributes)
        {
          std::string v;
          Error tmp{};
          if (!Parser::decodeEntities(a.value, v, &tmp))
          {
            if (errOut)
            {
              *errOut = tmp;
            }
            return nullptr;
          }
          elem->attributes.push_back(Node::Attr{std::string(a.name), std::move(v)});
        }
        Node *parent = stack.back();
        Node *raw = elem.get();
        parent->children.push_back(std::move(elem));
        stack.push_back(raw);
        break;
      }
      case TokenKind::EmptyElement:
      {
        auto elem = std::make_unique<Node>();
        elem->type = NodeType::Element;
        elem->name = std::string(t.name);
        elem->attributes.reserve(t.attributes.size());
        for (const auto &a : t.attributes)
        {
          std::string v;
          Error tmp{};
          if (!Parser::decodeEntities(a.value, v, &tmp))
          {
            if (errOut)
            {
              *errOut = tmp;
            }
            return nullptr;
          }
          elem->attributes.push_back(Node::Attr{std::string(a.name), std::move(v)});
        }
        Node *parent = stack.back();
        parent->children.push_back(std::move(elem));
        break;
      }
      case TokenKind::EndElement:
      {
        if (stack.size() <= 1)
        {
          if (errOut)
          {
            *errOut = Error{t.offset, t.line, t.column, "unbalanced end element"};
          }
          return nullptr;
        }
        Node *closed = stack.back();
        (void)closed;
        stack.pop_back();
        break;
      }
      case TokenKind::Text:
      {
        std::string v;
        Error tmp{};
        if (!Parser::decodeEntities(t.text, v, &tmp))
        {
          if (errOut)
          {
            *errOut = tmp;
          }
          return nullptr;
        }
        if (!v.empty())
        {
          auto n = std::make_unique<Node>();
          n->type = NodeType::Text;
          n->value = std::move(v);
          stack.back()->children.push_back(std::move(n));
        }
        break;
      }
      case TokenKind::CData:
      {
        auto n = std::make_unique<Node>();
        n->type = NodeType::CData;
        n->value = std::string(t.text);
        stack.back()->children.push_back(std::move(n));
        break;
      }
      case TokenKind::Comment:
      {
        auto n = std::make_unique<Node>();
        n->type = NodeType::Comment;
        n->value = std::string(t.text);
        stack.back()->children.push_back(std::move(n));
        break;
      }
      case TokenKind::ProcessingInstruction:
      {
        auto n = std::make_unique<Node>();
        n->type = NodeType::ProcessingInstruction;
        n->name = std::string(t.name);
        n->value = std::string(t.text);
        stack.back()->children.push_back(std::move(n));
        break;
      }
      case TokenKind::XmlDecl:
      case TokenKind::Doctype:
      case TokenKind::Invalid:
      case TokenKind::Eof:
      default:
        break;
      }
    }

    if (const Error *e = parser.error())
    {
      if (errOut)
      {
        *errOut = *e;
      }
      return nullptr;
    }
    if (stack.size() != 1)
    {
      if (errOut)
      {
        *errOut = Error{0, 0, 0, "unclosed elements at end of document"};
      }
      return nullptr;
    }
    return doc;
  }
};
#endif // IORA_XML_ENABLE_DOM

} // namespace xml
} // namespace parsers
} // namespace iora