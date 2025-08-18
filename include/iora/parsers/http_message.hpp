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

#include <string>
#include <map>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <fstream>
#include <ctime>
#include <random>

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

  /// \brief Convert string to HttpMethod
  inline HttpMethod parseMethod(const std::string& method)
  {
    std::string upperMethod = method;
    std::transform(upperMethod.begin(), upperMethod.end(), upperMethod.begin(),
                   ::toupper);

    if (upperMethod == "GET")
      return HttpMethod::GET;
    if (upperMethod == "POST")
      return HttpMethod::POST;
    if (upperMethod == "PUT")
      return HttpMethod::PUT;
    if (upperMethod == "DELETE")
      return HttpMethod::DELETE;
    if (upperMethod == "HEAD")
      return HttpMethod::HEAD;
    if (upperMethod == "OPTIONS")
      return HttpMethod::OPTIONS;
    if (upperMethod == "PATCH")
      return HttpMethod::PATCH;
    if (upperMethod == "CONNECT")
      return HttpMethod::CONNECT;
    if (upperMethod == "TRACE")
      return HttpMethod::TRACE;

    throw std::invalid_argument("Unknown HTTP method: " + method);
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

    static HttpVersion parse(const std::string& version)
    {
      if (version.substr(0, 5) != "HTTP/")
      {
        throw std::invalid_argument("Invalid HTTP version format");
      }

      auto dotPos = version.find('.', 5);
      if (dotPos == std::string::npos)
      {
        throw std::invalid_argument("Invalid HTTP version format");
      }

      HttpVersion result;
      result.major = std::stoi(version.substr(5, dotPos - 5));
      result.minor = std::stoi(version.substr(dotPos + 1));
      return result;
    }
  };

  /// \brief Case-insensitive string comparison for headers
  struct CaseInsensitiveCompare
  {
    bool operator()(const std::string& a, const std::string& b) const
    {
      return std::lexicographical_compare(
          a.begin(), a.end(), b.begin(), b.end(),
          [](char a, char b) { return std::tolower(a) < std::tolower(b); });
    }
  };

  /// \brief HTTP headers with case-insensitive keys
  using HttpHeaders =
      std::map<std::string, std::string, CaseInsensitiveCompare>;

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
    std::uint16_t getEffectivePort() const
    {
      return port == 0 ? getDefaultPort() : port;
    }

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
  inline ParsedUrl parseUrl(const std::string& url)
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
      std::transform(result.scheme.begin(), result.scheme.end(),
                     result.scheme.begin(), ::tolower);
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
    HttpRequest(HttpMethod m, const std::string& u) : method(m), uri(u) {}

    /// \brief Get header value (case-insensitive)
    std::string getHeader(const std::string& name) const
    {
      auto it = headers.find(name);
      return it != headers.end() ? it->second : std::string{};
    }

    /// \brief Set header value (case-insensitive)
    void setHeader(const std::string& name, const std::string& value)
    {
      headers[name] = value;
    }

    /// \brief Check if header exists
    bool hasHeader(const std::string& name) const
    {
      return headers.find(name) != headers.end();
    }

    /// \brief Set content type and body
    void setJsonBody(const std::string& jsonContent)
    {
      body = jsonContent;
      setHeader("Content-Type", "application/json");
      setHeader("Content-Length", std::to_string(body.size()));
    }

    /// \brief Set form data body
    void setFormBody(const std::string& formContent)
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
      ss << toString(method) << " " << uri << " " << version.toString()
         << "\r\n";

      // Headers
      for (const auto& [key, value] : headers)
      {
        ss << key << ": " << value << "\r\n";
      }

      ss << "\r\n"; // End of headers

      // Body
      ss << body;

      return ss.str();
    }

    /// \brief Parse request from wire format
    static HttpRequest fromWireFormat(const std::string& data)
    {
      HttpRequest request;

      auto headerEnd = data.find("\r\n\r\n");
      if (headerEnd == std::string::npos)
      {
        throw std::invalid_argument(
            "Invalid HTTP request: missing header terminator");
      }

      std::string headerSection = data.substr(0, headerEnd);
      request.body = data.substr(headerEnd + 4);

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
          parseRequestLine(line, request);
          firstLine = false;
        }
        else if (!line.empty())
        {
          parseHeaderLine(line, request.headers);
        }
      }

      return request;
    }

  private:
    static void parseRequestLine(const std::string& line, HttpRequest& request)
    {
      std::istringstream iss(line);
      std::string methodStr, versionStr;
      iss >> methodStr >> request.uri >> versionStr;

      request.method = parseMethod(methodStr);
      request.version = HttpVersion::parse(versionStr);
    }

    static void parseHeaderLine(const std::string& line, HttpHeaders& headers)
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

        headers[key] = value;
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
    HttpResponse(int code, const std::string& text = "")
      : statusCode(code), statusText(text)
    {
    }

    /// \brief Check if response indicates success
    bool isSuccess() const { return statusCode >= 200 && statusCode < 300; }

    /// \brief Check if response is informational
    bool isInformational() const
    {
      return statusCode >= 100 && statusCode < 200;
    }

    /// \brief Check if response is redirection
    bool isRedirection() const { return statusCode >= 300 && statusCode < 400; }

    /// \brief Check if response is client error
    bool isClientError() const { return statusCode >= 400 && statusCode < 500; }

    /// \brief Check if response is server error
    bool isServerError() const { return statusCode >= 500 && statusCode < 600; }

    /// \brief Get header value (case-insensitive)
    std::string getHeader(const std::string& name) const
    {
      auto it = headers.find(name);
      return it != headers.end() ? it->second : std::string{};
    }

    /// \brief Set header value
    void setHeader(const std::string& name, const std::string& value)
    {
      headers[name] = value;
    }

    /// \brief Check if header exists
    bool hasHeader(const std::string& name) const
    {
      return headers.find(name) != headers.end();
    }

    /// \brief Set JSON response body
    void setJsonBody(const std::string& jsonContent)
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
      ss << version.toString() << " " << statusCode << " " << statusText
         << "\r\n";

      // Headers
      for (const auto& [key, value] : headers)
      {
        ss << key << ": " << value << "\r\n";
      }

      ss << "\r\n"; // End of headers

      // Body
      ss << body;

      return ss.str();
    }

    /// \brief Parse response from wire format
    static HttpResponse fromWireFormat(const std::string& data)
    {
      HttpResponse response;

      auto headerEnd = data.find("\r\n\r\n");
      if (headerEnd == std::string::npos)
      {
        throw std::invalid_argument(
            "Invalid HTTP response: missing header terminator");
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
    static void parseStatusLine(const std::string& line, HttpResponse& response)
    {
      std::istringstream iss(line);
      std::string version;
      iss >> version >> response.statusCode;

      // Get rest of line as status text
      std::string remaining;
      std::getline(iss, remaining);
      response.statusText =
          remaining.empty() ? "" : remaining.substr(1); // Remove leading space

      response.version = HttpVersion::parse(version);
    }

    static void parseHeaderLine(const std::string& line, HttpHeaders& headers)
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

        headers[key] = value;
      }
    }

    static std::string parseChunkedBody(const std::string& chunkedData)
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
    void addField(const std::string& name, const std::string& value)
    {
      Part part;
      part.name = name;
      part.content = value;
      _parts.push_back(part);
    }

    /// \brief Add file field
    void addFile(const std::string& name, const std::string& filename,
                 const std::string& content,
                 const std::string& contentType = "application/octet-stream")
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
    std::string getContentType() const
    {
      return "multipart/form-data; boundary=" + _boundary;
    }

    /// \brief Build multipart body
    std::string build() const
    {
      std::ostringstream body;

      for (const auto& part : _parts)
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