// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
/// \file http_message.hpp
/// \brief Reusable HTTP message structures for both client and server
/// implementations
///
/// This provides common HTTP message handling that can be shared between
/// HttpClient and WebhookServer implementations, replacing external
/// dependencies like cpr and cpp-httplib with homegrown, integrated solutions.
///

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace iora
{
namespace network
{

/// \brief HTTP method enumeration
enum class HttpMethod
{
  GET,
  POST,
  PUT,
  DELETE,
  HEAD,
  OPTIONS,
  PATCH,
  CONNECT,
  TRACE
};

/// \brief Convert HttpMethod to string
inline std::string toString(HttpMethod method)
{
  switch (method)
  {
  case HttpMethod::GET:
    return "GET";
  case HttpMethod::POST:
    return "POST";
  case HttpMethod::PUT:
    return "PUT";
  case HttpMethod::DELETE:
    return "DELETE";
  case HttpMethod::HEAD:
    return "HEAD";
  case HttpMethod::OPTIONS:
    return "OPTIONS";
  case HttpMethod::PATCH:
    return "PATCH";
  case HttpMethod::CONNECT:
    return "CONNECT";
  case HttpMethod::TRACE:
    return "TRACE";
  default:
    return "GET";
  }
}

/// \brief Parse error carrying the HTTP status the origin server should return.
/// Thrown by the request parser so the server can answer the RFC-appropriate
/// status (400 Bad Request for a malformed token, 501 Not Implemented for a
/// well-formed but unsupported method) instead of a blanket 500.
class HttpRequestError : public std::runtime_error
{
public:
  HttpRequestError(int status, const std::string &message)
      : std::runtime_error(message), _status(status)
  {
  }
  int status() const noexcept { return _status; }

private:
  int _status;
};

/// \brief True iff `s` is a non-empty RFC 9110 §5.6.2 token (1*tchar): every
/// character is a tchar (ALPHA / DIGIT / "!#$%&'*+-.^_`|~"). Used to distinguish
/// a malformed method token (400) from a well-formed unsupported one (501).
inline bool isHttpToken(const std::string &s)
{
  if (s.empty())
  {
    return false;
  }
  static const std::string kTcharPunct = "!#$%&'*+-.^_`|~";
  for (unsigned char c : s)
  {
    // Locale-INDEPENDENT ASCII classification: std::isalnum is locale-sensitive
    // and a non-C LC_CTYPE could classify high bytes (e.g. Latin-1 0xC0-0xFF) as
    // alpha, over-accepting non-tchar bytes (web-M1). The tchar grammar is pure
    // ASCII, so test ranges directly.
    const bool tchar = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                       (c >= '0' && c <= '9') ||
                       (kTcharPunct.find(static_cast<char>(c)) != std::string::npos);
    if (!tchar)
    {
      return false;
    }
  }
  return true;
}

/// \brief Convert a request method token to HttpMethod. Method names are
/// CASE-SENSITIVE per RFC 9110 §9.1 (registered methods are uppercase). A
/// well-formed but unrecognized token throws HttpRequestError(501); a malformed
/// token throws HttpRequestError(400).
inline HttpMethod parseMethod(const std::string &method)
{
  if (method == "GET")
  {
    return HttpMethod::GET;
  }
  if (method == "POST")
  {
    return HttpMethod::POST;
  }
  if (method == "PUT")
  {
    return HttpMethod::PUT;
  }
  if (method == "DELETE")
  {
    return HttpMethod::DELETE;
  }
  if (method == "HEAD")
  {
    return HttpMethod::HEAD;
  }
  if (method == "OPTIONS")
  {
    return HttpMethod::OPTIONS;
  }
  if (method == "PATCH")
  {
    return HttpMethod::PATCH;
  }
  if (method == "CONNECT")
  {
    return HttpMethod::CONNECT;
  }
  if (method == "TRACE")
  {
    return HttpMethod::TRACE;
  }

  if (!isHttpToken(method))
  {
    throw HttpRequestError(400, "Malformed HTTP method token");
  }
  throw HttpRequestError(501, "Unsupported HTTP method: " + method);
}

/// \brief HTTP version representation
struct HttpVersion
{
  int major{1};
  int minor{1};

  std::string toString() const
  {
    return "HTTP/" + std::to_string(major) + "." + std::to_string(minor);
  }

  static HttpVersion parse(const std::string &version)
  {
    // RFC 9112 §2.3: HTTP-version = "HTTP" "/" DIGIT "." DIGIT — EXACTLY one
    // DIGIT per component (8 chars total), no sign/whitespace/leading-zero/
    // multi-digit/trailing junk. std::stoi is far too lenient (it skips leading
    // whitespace, accepts a sign, accepts multi-digit, and silently ignores
    // trailing non-digits), which both over-accepts malformed versions (e.g.
    // "HTTP/1.1xyz" -> 1.1) and misroutes them (e.g. "HTTP/11.0" -> major 11 ->
    // 505 instead of the correct 400). Parse the two digits explicitly.
    if (version.size() != 8 || version.compare(0, 5, "HTTP/") != 0 ||
        version[5] < '0' || version[5] > '9' || version[6] != '.' ||
        version[7] < '0' || version[7] > '9')
    {
      throw std::invalid_argument("Malformed HTTP-version");
    }
    HttpVersion result;
    result.major = version[5] - '0';
    result.minor = version[7] - '0';
    return result;
  }
};

/// \brief Case-insensitive string comparison for headers. HTTP field names are
/// US-ASCII tokens (RFC 9110 §5.1), so fold case with a locale-INDEPENDENT ASCII
/// fold — std::tolower(char) is locale-sensitive and is UB for a negative char
/// (bytes >= 0x80), which would mis-order or mis-compare non-ASCII header bytes.
struct CaseInsensitiveCompare
{
  static char asciiLower(unsigned char c)
  {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : static_cast<char>(c);
  }
  bool operator()(const std::string &a, const std::string &b) const
  {
    return std::lexicographical_compare(
      a.begin(), a.end(), b.begin(), b.end(), [](char x, char y)
      { return asciiLower(static_cast<unsigned char>(x)) < asciiLower(static_cast<unsigned char>(y)); });
  }
};

/// \brief HTTP headers with case-insensitive keys
using HttpHeaders = std::map<std::string, std::string, CaseInsensitiveCompare>;

namespace detail
{
/// \brief Whether a header field is a comma-separated list (RFC 9110 §5.3) whose
/// repeated field-lines may be combined with ", ".
///
/// Only fields whose ABNF defines them as a #list are combinable. Combining a
/// non-list field that carries intrinsic commas (Set-Cookie, Retry-After's HTTP-date,
/// WWW-Authenticate, Date/Expires/Last-Modified) would corrupt it, so this is an
/// ALLOW-LIST (safe-by-default: an unknown header keeps last-wins, never corrupted).
/// X-Forwarded-Host / X-Forwarded-Proto are deliberately EXCLUDED — they are
/// single-valued-per-hop, do not accumulate, and the protocol-correct handling of
/// duplicates is ignore, not comma-join.
inline bool isListValuedHeader(const std::string &name)
{
  static const std::set<std::string, CaseInsensitiveCompare> kListValued = {
    "X-Forwarded-For", "Forwarded", "Via"};
  return kListValued.count(name) != 0;
}

/// \brief Insert a parsed header, or combine a repeated field-line.
///
/// RFC 9110 §5.3: repeated field-lines of a comma-list field are combined by appending
/// each subsequent value, in order, separated by ", ". Non-list fields keep last-wins
/// (preserving the prior behavior). PRECONDITION: \p value is already OWS-trimmed by the
/// caller (parseHeaderLine), so an all-whitespace value arrives as "" and the empty
/// element is skipped (RFC 9110 §5.3 allows empty list elements; we drop them).
inline void addOrCombineHeader(HttpHeaders &headers, const std::string &key,
                               const std::string &value)
{
  auto it = headers.find(key);
  if (it == headers.end())
  {
    headers.emplace(key, value);
    return;
  }
  if (isListValuedHeader(key))
  {
    if (value.empty())
    {
      return; // skip empty list element (keep existing combined value)
    }
    if (it->second.empty())
    {
      it->second = value;
    }
    else
    {
      it->second.append(", ").append(value);
    }
  }
  else
  {
    it->second = value; // non-list field: last-wins (prior behavior)
  }
}
} // namespace detail

/// \brief URL parsing structure
struct ParsedUrl
{
  std::string scheme; // http, https
  std::string host;
  std::uint16_t port{0}; // 0 means use default for scheme
  std::string path;
  std::string query;
  std::string fragment;

  bool isHttps() const { return scheme == "https"; }
  std::uint16_t getDefaultPort() const { return isHttps() ? 443 : 80; }
  std::uint16_t getEffectivePort() const { return port == 0 ? getDefaultPort() : port; }

  std::string getPathWithQuery() const
  {
    std::string result = path.empty() ? "/" : path;
    if (!query.empty())
    {
      result += "?" + query;
    }
    return result;
  }
};

/// \brief Parse URL into components
inline ParsedUrl parseUrl(const std::string &url)
{
  ParsedUrl result;

  if (url.empty())
  {
    throw std::invalid_argument("Empty URL");
  }

  std::string remaining = url;

  // Extract scheme
  auto schemeEnd = remaining.find("://");
  if (schemeEnd != std::string::npos)
  {
    result.scheme = remaining.substr(0, schemeEnd);
    std::transform(result.scheme.begin(), result.scheme.end(), result.scheme.begin(), ::tolower);
    remaining = remaining.substr(schemeEnd + 3);
  }
  else
  {
    throw std::invalid_argument("URL missing scheme (http:// or https://)");
  }

  // Extract fragment first (after #)
  auto fragmentPos = remaining.find('#');
  if (fragmentPos != std::string::npos)
  {
    result.fragment = remaining.substr(fragmentPos + 1);
    remaining = remaining.substr(0, fragmentPos);
  }

  // Extract path and query
  auto pathStart = remaining.find('/');
  std::string hostPart;
  if (pathStart != std::string::npos)
  {
    hostPart = remaining.substr(0, pathStart);
    std::string pathPart = remaining.substr(pathStart);

    // Separate path and query
    auto queryStart = pathPart.find('?');
    if (queryStart != std::string::npos)
    {
      result.path = pathPart.substr(0, queryStart);
      result.query = pathPart.substr(queryStart + 1);
    }
    else
    {
      result.path = pathPart;
    }
  }
  else
  {
    hostPart = remaining;
    result.path = "/";
  }

  // Parse host and port
  auto portPos = hostPart.find(':');
  if (portPos != std::string::npos)
  {
    result.host = hostPart.substr(0, portPos);
    std::string portStr = hostPart.substr(portPos + 1);
    if (!portStr.empty())
    {
      result.port = static_cast<std::uint16_t>(std::stoi(portStr));
    }
  }
  else
  {
    result.host = hostPart;
  }

  return result;
}

/// \brief HTTP request message
class HttpRequest
{
public:
  HttpMethod method{HttpMethod::GET};
  std::string uri; // Path + query string
  HttpVersion version{1, 1};
  HttpHeaders headers;
  std::string body;

  /// \brief Construct empty request
  HttpRequest() = default;

  /// \brief Construct request with method and URI
  HttpRequest(HttpMethod m, const std::string &u) : method(m), uri(u) {}

  /// \brief Get header value (case-insensitive)
  std::string getHeader(const std::string &name) const
  {
    auto it = headers.find(name);
    return it != headers.end() ? it->second : std::string{};
  }

  /// \brief Set header value (case-insensitive)
  void setHeader(const std::string &name, const std::string &value) { headers[name] = value; }

  /// \brief Check if header exists
  bool hasHeader(const std::string &name) const { return headers.find(name) != headers.end(); }

  /// \brief Set content type and body
  void setJsonBody(const std::string &jsonContent)
  {
    body = jsonContent;
    setHeader("Content-Type", "application/json");
    setHeader("Content-Length", std::to_string(body.size()));
  }

  /// \brief Set form data body
  void setFormBody(const std::string &formContent)
  {
    body = formContent;
    setHeader("Content-Type", "application/x-www-form-urlencoded");
    setHeader("Content-Length", std::to_string(body.size()));
  }

  /// \brief Convert to HTTP wire format
  std::string toWireFormat() const
  {
    std::ostringstream ss;

    // Request line
    ss << toString(method) << " " << uri << " " << version.toString() << "\r\n";

    // Headers
    for (const auto &[key, value] : headers)
    {
      ss << key << ": " << value << "\r\n";
    }

    ss << "\r\n"; // End of headers

    // Body
    ss << body;

    return ss.str();
  }

  /// \brief Parse request from wire format
  static HttpRequest fromWireFormat(const std::string &data)
  {
    HttpRequest request;

    auto headerEnd = data.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
    {
      throw std::invalid_argument("Invalid HTTP request: missing header terminator");
    }

    std::string headerSection = data.substr(0, headerEnd);
    request.body = data.substr(headerEnd + 4);

    std::istringstream headerStream(headerSection);
    std::string line;
    bool firstLine = true;

    int hostCount = 0;
    while (std::getline(headerStream, line))
    {
      // Remove \r if present
      if (!line.empty() && line.back() == '\r')
      {
        line.pop_back();
      }

      if (firstLine)
      {
        parseRequestLine(line, request);
        firstLine = false;
        continue;
      }
      if (line.empty())
      {
        continue;
      }
      // RFC 9112 §5.2: obsolete line folding (a header field-line beginning with SP
      // or HTAB, continuing the previous field) MUST be rejected by a server.
      if (line.front() == ' ' || line.front() == '\t')
      {
        throw HttpRequestError(400, "Obsolete line folding (obs-fold) is not allowed");
      }
      // RFC 9112 §3.2 / RFC 9110 §7.2: count Host field-lines (a request MUST contain
      // exactly one Host; the single-value headers map would otherwise hide a duplicate).
      const auto colonPos = line.find(':');
      if (colonPos != std::string::npos)
      {
        std::string name = line.substr(0, colonPos);
        name.erase(0, name.find_first_not_of(" \t"));
        name.erase(name.find_last_not_of(" \t") + 1);
        static const CaseInsensitiveCompare ci;
        if (!ci(name, "Host") && !ci("Host", name)) // case-insensitive equality
        {
          ++hostCount;
        }
      }
      parseHeaderLine(line, request.headers);
    }

    // RFC 9112 §3.2: more than one Host field-line -> 400 (host-confusion / smuggling).
    if (hostCount > 1)
    {
      throw HttpRequestError(400, "Multiple Host header fields");
    }
    // RFC 9110 §7.2 / RFC 9112 §3.2: HTTP/1.1+ requests MUST send a Host. HTTP/1.0
    // (minor == 0) is exempt.
    if (request.version.minor >= 1 && hostCount == 0)
    {
      throw HttpRequestError(400, "Missing Host header field (required for HTTP/1.1)");
    }
    // RFC 9112 §3.2: a Host header field with an invalid (here: empty) field value is
    // a 400. The stored value is already OWS-trimmed by parseHeaderLine, so an
    // OWS-only value reaches here as "". Checked regardless of version (an empty
    // authority is meaningless).
    if (hostCount >= 1)
    {
      auto hostIt = request.headers.find("Host");
      if (hostIt != request.headers.end() && hostIt->second.empty())
      {
        throw HttpRequestError(400, "Empty Host header field value");
      }
    }

    return request;
  }

private:
  /// \brief Max request-target length (RFC 9112 §3): over-length -> 414. Kept
  /// well below SessionInfo::MAX_HEADER_SIZE (64 KB) so the deterministic 414
  /// fires before the transport's silent header-size close. (Tracker 2026-06-02-1.)
  static constexpr std::size_t MAX_REQUEST_TARGET_SIZE = 8192;

  static void parseRequestLine(const std::string &line, HttpRequest &request)
  {
    // RFC 9112 §3: request-line = method SP request-target SP HTTP-version, with
    // EXACTLY one SP (0x20) between the three fields. Lenient whitespace handling
    // is a §3 MAY but enables request smuggling across multiple recipients, so
    // iora enforces strict single-SP and rejects any other inter-field/in-field
    // whitespace with 400 (§3 SHOULD). Explicit SP-index split — NOT
    // std::istringstream, which collapses whitespace runs and skips leading/
    // trailing whitespace. (Tracker 2026-06-02-1.) The caller has already stripped
    // a single trailing CR, so an embedded CR/LF is rejected by the byte checks.
    const std::size_t p1 = line.find(' ');
    const std::size_t p2 = (p1 == std::string::npos) ? std::string::npos : line.find(' ', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos || p1 == 0 || p2 == p1 + 1 ||
        p2 + 1 >= line.size())
    {
      // Missing/extra SP, empty method/target/version, or no version field.
      throw HttpRequestError(400,
                             "Malformed request line (RFC 9112 §3: method SP target SP version)");
    }
    const std::string methodStr = line.substr(0, p1);
    std::string target = line.substr(p1 + 1, p2 - (p1 + 1));
    const std::string versionStr = line.substr(p2 + 1);

    // No other whitespace/CTL inside the method or version fields. A SP in the
    // version field (a 3rd separator / 4th token / trailing SP) is rejected here,
    // subsuming the former extra-token check. Locale-independent unsigned-char
    // range test (never std::iscntrl/isspace).
    for (char c : methodStr)
    {
      if (static_cast<unsigned char>(c) < 0x21)
      {
        throw HttpRequestError(400, "Malformed request line (whitespace/control in method)");
      }
    }
    for (char c : versionStr)
    {
      if (static_cast<unsigned char>(c) < 0x21)
      {
        throw HttpRequestError(400, "Malformed request line (whitespace/control in version)");
      }
    }

    // Request-target octet validation (RFC 9112 §3.2 / RFC 3986). Length first
    // (RFC 9112 §3 MUST: over-long request-target -> 414 URI Too Long), then
    // reject CTL (<0x20) and DEL (0x7F) -> 400 (log/response-splitting surface).
    // Non-ASCII bytes (0x80-0xFF) are ACCEPTED as opaque octets — browsers/curl
    // send raw UTF-8 in the path and iora routing is byte-exact; bytes are never
    // transformed. Request-target FORM (origin/absolute/authority/asterisk) is
    // NOT structurally validated, so 'OPTIONS *' and 'CONNECT host:port' parse.
    if (target.size() > MAX_REQUEST_TARGET_SIZE)
    {
      throw HttpRequestError(414, "Request-target too long");
    }
    for (char c : target)
    {
      const unsigned char u = static_cast<unsigned char>(c);
      if (u < 0x20 || u == 0x7F)
      {
        throw HttpRequestError(400, "Malformed request-target (control character)");
      }
    }

    request.uri = std::move(target);
    request.method = parseMethod(methodStr); // throws HttpRequestError(400/501)
    // A malformed or missing HTTP-version in the request line is a client error
    // (400 Bad Request, RFC 9110 §15.5.1 / RFC 9112 §2.3), NOT a 500 (web-M3).
    // HttpVersion::parse throws std::invalid_argument/std::out_of_range; the
    // response parser also uses it, so map to 400 HERE (request path only) rather
    // than changing HttpVersion::parse globally.
    try
    {
      request.version = HttpVersion::parse(versionStr);
    }
    catch (const HttpRequestError &)
    {
      throw; // already carries a request status
    }
    catch (const std::exception &)
    {
      throw HttpRequestError(400, "Malformed or missing HTTP version in request line");
    }

    // RFC 9110 §15.5.6: a well-formed but unsupported HTTP MAJOR version ->
    // 505 HTTP Version Not Supported. iora speaks HTTP/1.x only, so any major
    // other than 1 (e.g. HTTP/0.9, HTTP/2.0, HTTP/3.0) is rejected; the minor
    // version is forward-compatible (1.0 and 1.1 both accepted).
    if (request.version.major != 1)
    {
      throw HttpRequestError(505, "Unsupported HTTP major version");
    }
  }

  static void parseHeaderLine(const std::string &line, HttpHeaders &headers)
  {
    auto colonPos = line.find(':');
    if (colonPos != std::string::npos)
    {
      std::string key = line.substr(0, colonPos);
      std::string value = line.substr(colonPos + 1);

      // Trim whitespace
      key.erase(0, key.find_first_not_of(" \t"));
      key.erase(key.find_last_not_of(" \t") + 1);
      value.erase(0, value.find_first_not_of(" \t"));
      value.erase(value.find_last_not_of(" \t") + 1);

      detail::addOrCombineHeader(headers, key, value);
    }
  }
};

/// \brief HTTP response message
class HttpResponse
{
public:
  HttpVersion version{1, 1};
  int statusCode{200};
  std::string statusText{"OK"};
  HttpHeaders headers;
  std::string body;

  /// \brief Construct empty response
  HttpResponse() = default;

  /// \brief Construct response with status
  HttpResponse(int code, const std::string &text = "") : statusCode(code), statusText(text) {}

  /// \brief Check if response indicates success
  bool isSuccess() const { return statusCode >= 200 && statusCode < 300; }

  /// \brief Check if response is informational
  bool isInformational() const { return statusCode >= 100 && statusCode < 200; }

  /// \brief Check if response is redirection
  bool isRedirection() const { return statusCode >= 300 && statusCode < 400; }

  /// \brief Check if response is client error
  bool isClientError() const { return statusCode >= 400 && statusCode < 500; }

  /// \brief Check if response is server error
  bool isServerError() const { return statusCode >= 500 && statusCode < 600; }

  /// \brief Get header value (case-insensitive)
  std::string getHeader(const std::string &name) const
  {
    auto it = headers.find(name);
    return it != headers.end() ? it->second : std::string{};
  }

  /// \brief Set header value
  void setHeader(const std::string &name, const std::string &value) { headers[name] = value; }

  /// \brief Check if header exists
  bool hasHeader(const std::string &name) const { return headers.find(name) != headers.end(); }

  /// \brief Set JSON response body
  void setJsonBody(const std::string &jsonContent)
  {
    body = jsonContent;
    setHeader("Content-Type", "application/json");
    setHeader("Content-Length", std::to_string(body.size()));
  }

  /// \brief Convert to HTTP wire format
  std::string toWireFormat() const
  {
    std::ostringstream ss;

    // Status line
    ss << version.toString() << " " << statusCode << " " << statusText << "\r\n";

    // Headers
    for (const auto &[key, value] : headers)
    {
      ss << key << ": " << value << "\r\n";
    }

    ss << "\r\n"; // End of headers

    // Body
    ss << body;

    return ss.str();
  }

  /// \brief Parse response from wire format
  static HttpResponse fromWireFormat(const std::string &data)
  {
    HttpResponse response;

    auto headerEnd = data.find("\r\n\r\n");
    if (headerEnd == std::string::npos)
    {
      throw std::invalid_argument("Invalid HTTP response: missing header terminator");
    }

    std::string headerSection = data.substr(0, headerEnd);
    response.body = data.substr(headerEnd + 4);

    std::istringstream headerStream(headerSection);
    std::string line;
    bool firstLine = true;

    while (std::getline(headerStream, line))
    {
      // Remove \r if present
      if (!line.empty() && line.back() == '\r')
      {
        line.pop_back();
      }

      if (firstLine)
      {
        parseStatusLine(line, response);
        firstLine = false;
      }
      else if (!line.empty())
      {
        parseHeaderLine(line, response.headers);
      }
    }

    // Handle chunked transfer encoding
    auto transferEncoding = response.getHeader("transfer-encoding");
    if (transferEncoding.find("chunked") != std::string::npos)
    {
      response.body = parseChunkedBody(response.body);
    }

    return response;
  }

private:
  static void parseStatusLine(const std::string &line, HttpResponse &response)
  {
    std::istringstream iss(line);
    std::string version;
    iss >> version >> response.statusCode;

    // Get rest of line as status text
    std::string remaining;
    std::getline(iss, remaining);
    response.statusText = remaining.empty() ? "" : remaining.substr(1); // Remove leading space

    response.version = HttpVersion::parse(version);
  }

  static void parseHeaderLine(const std::string &line, HttpHeaders &headers)
  {
    auto colonPos = line.find(':');
    if (colonPos != std::string::npos)
    {
      std::string key = line.substr(0, colonPos);
      std::string value = line.substr(colonPos + 1);

      // Trim whitespace
      key.erase(0, key.find_first_not_of(" \t"));
      key.erase(key.find_last_not_of(" \t") + 1);
      value.erase(0, value.find_first_not_of(" \t"));
      value.erase(value.find_last_not_of(" \t") + 1);

      detail::addOrCombineHeader(headers, key, value);
    }
  }

  static std::string parseChunkedBody(const std::string &chunkedData)
  {
    std::string result;
    std::istringstream stream(chunkedData);
    std::string line;

    while (std::getline(stream, line))
    {
      // Remove \r if present
      if (!line.empty() && line.back() == '\r')
      {
        line.pop_back();
      }

      if (line.empty())
        continue;

      // Parse chunk size (hex)
      std::size_t chunkSize;
      try
      {
        chunkSize = std::stoull(line, nullptr, 16);
      }
      catch (...)
      {
        break; // Invalid chunk size
      }

      if (chunkSize == 0)
      {
        // End of chunks
        break;
      }

      // Read chunk data
      std::vector<char> chunkData(chunkSize);
      stream.read(chunkData.data(), chunkSize);
      std::streamsize bytesRead = stream.gcount();
      result.append(chunkData.begin(), chunkData.begin() + bytesRead);

      // Skip trailing CRLF after chunk data
      std::getline(stream, line);
    }

    return result;
  }
};

/// \brief Multipart form data builder
class MultipartFormData
{
public:
  struct Part
  {
    std::string name;
    std::string filename;
    std::string contentType;
    std::string content;
  };

private:
  std::vector<Part> _parts;
  std::string _boundary;

public:
  MultipartFormData()
  {
    // Generate random boundary
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    _boundary = "----IoraBoundary";
    for (int i = 0; i < 16; ++i)
    {
      _boundary += "0123456789abcdef"[dis(gen)];
    }
  }

  /// \brief Add text field
  void addField(const std::string &name, const std::string &value)
  {
    Part part;
    part.name = name;
    part.content = value;
    _parts.push_back(part);
  }

  /// \brief Add file field
  void addFile(const std::string &name, const std::string &filename, const std::string &content,
               const std::string &contentType = "application/octet-stream")
  {
    Part part;
    part.name = name;
    part.filename = filename;
    part.contentType = contentType;
    part.content = content;
    _parts.push_back(part);
  }

  /// \brief Get boundary string
  std::string getBoundary() const { return _boundary; }

  /// \brief Get content type header value
  std::string getContentType() const { return "multipart/form-data; boundary=" + _boundary; }

  /// \brief Build multipart body
  std::string build() const
  {
    std::ostringstream body;

    for (const auto &part : _parts)
    {
      body << "--" << _boundary << "\r\n";
      body << "Content-Disposition: form-data; name=\"" << part.name << "\"";

      if (!part.filename.empty())
      {
        body << "; filename=\"" << part.filename << "\"";
      }

      body << "\r\n";

      if (!part.contentType.empty())
      {
        body << "Content-Type: " << part.contentType << "\r\n";
      }

      body << "\r\n";
      body << part.content << "\r\n";
    }

    body << "--" << _boundary << "--\r\n";

    return body.str();
  }
};

} // namespace network
} // namespace iora