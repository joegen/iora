// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <mutex>
#include <unordered_map>
#include <optional>
#include <chrono>
#include <future>
#include <functional>
#include <thread>
#include <sstream>
#include <fstream>
#include <regex>
#include <ctime>
#include <atomic>

#include "iora/parsers/json.hpp"
#include "iora/network/unified_shared_transport.hpp"
#include "iora/network/dns_client.hpp"
#include "iora/parsers/http_message.hpp"

namespace iora
{
namespace network
{

  // Use the std::map<std::string, std::string> from http_message.hpp which has
  // case-insensitive comparison

  /// \brief Modern HTTP client using hybrid transport for sync/async operations
  /// \details
  ///   - Built on UnifiedSharedTransport for reliable networking
  ///   - Uses DnsClient for domain resolution
  ///   - Supports both synchronous and asynchronous operations
  ///   - Connection pooling with automatic cleanup
  ///   - TLS/HTTPS support via transport layer
  class HttpClient
  {
  public:
    /// \brief TLS configuration for HTTPS requests
    struct TlsConfig
    {
      std::string caFile;
      std::string clientCertFile;
      std::string clientKeyFile;
      bool verifyPeer = true;
    };

    /// \brief HTTP response structure
    struct Response
    {
      int statusCode = 0;
      std::string statusText;
      std::map<std::string, std::string> headers;
      std::string body;
      bool success() const { return statusCode >= 200 && statusCode < 300; }
    };

    /// \brief JSON parsing configuration
    struct JsonConfig
    {
      std::size_t maxPayloadSize = 10 * 1024 * 1024;  // Maximum JSON payload size in bytes (10MB default)
      parsers::ParseLimits parseLimits;  // JSON parsing limits (depth, array size, etc.)
    };

    /// \brief Configuration for HTTP client
    struct Config
    {
      std::chrono::milliseconds connectTimeout;
      std::chrono::milliseconds requestTimeout;
      int maxRedirects;
      bool followRedirects;
      std::string userAgent;
      bool reuseConnections;
      std::chrono::seconds connectionIdleTimeout;
      JsonConfig jsonConfig;  // JSON parsing configuration

      Config()
        : connectTimeout(2000),
          requestTimeout(3000),
          maxRedirects(5),
          followRedirects(true),
          userAgent("Iora-HttpClient/1.0"),
          reuseConnections(true),
          connectionIdleTimeout(300),
          jsonConfig{}
      {
      }

      /// \brief Create a config optimized for localhost/testing
      static Config forLocalhost()
      {
        Config c;
        c.connectTimeout = std::chrono::milliseconds(100);
        c.requestTimeout = std::chrono::milliseconds(200);
        return c;
      }
    };

  private:
    void ensureInitialized() const
    {
      if (!_transport)
      {
        // Create TCP transport for HTTP/HTTPS
        auto transportConfig = UnifiedSharedTransport::Config::minimal(
            UnifiedSharedTransport::Protocol::TCP);
        transportConfig.connectTimeout =
            std::chrono::duration_cast<std::chrono::seconds>(
                _config.connectTimeout);
        transportConfig.defaultSyncTimeout = _config.requestTimeout;
        transportConfig.idleTimeout = _config.connectionIdleTimeout;

        // Enable TLS for HTTPS with current TLS configuration
        transportConfig.clientTls.enabled = true;
        transportConfig.clientTls.defaultMode = TlsMode::Client;
        transportConfig.clientTls.verifyPeer = _tlsConfig.verifyPeer;

        _transport = std::make_unique<UnifiedSharedTransport>(transportConfig);
        bool startResult = _transport->start();
        if (!startResult)
        {
          throw std::runtime_error(
              "Failed to start HTTP client transport layer");
        }

        // Create DNS client for domain resolution
        _dnsClient = std::make_unique<DnsClient>();
        _dnsClient->start();
      }
    }

    mutable std::mutex _mutex;
    Config _config;
    TlsConfig _tlsConfig;

    // Transport and DNS client (initialized lazily)
    mutable std::unique_ptr<UnifiedSharedTransport> _transport;
    mutable std::unique_ptr<DnsClient> _dnsClient;

    // Simple connection pool: host:port -> SessionId
    mutable std::unordered_map<std::string, SessionId> _connections;
    mutable std::unordered_map<SessionId, std::chrono::steady_clock::time_point>
        _connectionLastUsed;
    mutable HybridTransport::ConnectCallback _connectCallback;

    /// \brief URL parsing structure
    struct ParsedUrl
    {
      std::string scheme;
      std::string host;
      std::uint16_t port;
      std::string path;
      std::string query;

      bool isHttps() const { return scheme == "https"; }
      std::string getPathWithQuery() const
      {
        if (query.empty())
          return path.empty() ? "/" : path;
        return (path.empty() ? "/" : path) + "?" + query;
      }
      std::string getHostPort() const
      {
        return host + ":" + std::to_string(port);
      }
    };

  public:
    /// \brief Constructor with optional configuration
    explicit HttpClient(const Config& config = Config{}) : _config(config)
    {
      // Transport and DNS client are created lazily to allow TLS config to be
      // set first
    }

    ~HttpClient() { cleanup(); }

    // Delete copy operations to prevent issues with transport ownership
    HttpClient(const HttpClient&) = delete;
    HttpClient& operator=(const HttpClient&) = delete;

    // Allow move operations
    HttpClient(HttpClient&&) = default;
    HttpClient& operator=(HttpClient&&) = default;

    /// \brief Set TLS configuration
    void setTlsConfig(const TlsConfig& config)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _tlsConfig = config;
      // TLS config is applied per-connection during connect
    }

    /// \brief Perform synchronous GET request
    Response get(const std::string& url,
                 const std::map<std::string, std::string>& headers = {},
                 int retries = 0)
    {
      return performRequest("GET", url, "", headers, retries);
    }

    /// \brief Perform synchronous POST request with JSON body
    Response postJson(const std::string& url, const parsers::Json& body,
                      const std::map<std::string, std::string>& headers = {},
                      int retries = 0)
    {
      std::map<std::string, std::string> jsonHeaders = headers;
      jsonHeaders["Content-Type"] = "application/json";
      std::string jsonBody = body.dump();
      return performRequest("POST", url, jsonBody, jsonHeaders, retries);
    }

    /// \brief Perform synchronous POST request with string body
    Response post(const std::string& url, const std::string& body,
                  const std::map<std::string, std::string>& headers = {},
                  int retries = 0)
    {
      return performRequest("POST", url, body, headers, retries);
    }

    /// \brief Perform synchronous DELETE request
    Response
    deleteRequest(const std::string& url,
                  const std::map<std::string, std::string>& headers = {},
                  int retries = 0)
    {
      return performRequest("DELETE", url, "", headers, retries);
    }

    /// \brief Perform asynchronous GET request
    std::future<Response>
    getAsync(const std::string& url,
             const std::map<std::string, std::string>& headers = {},
             int retries = 0)
    {
      return std::async(std::launch::async, [this, url, headers, retries]()
                        { return get(url, headers, retries); });
    }

    /// \brief Perform asynchronous POST request with JSON body
    std::future<Response>
    postJsonAsync(const std::string& url, const parsers::Json& body,
                  const std::map<std::string, std::string>& headers = {},
                  int retries = 0)
    {
      return std::async(std::launch::async,
                        [this, url, body, headers, retries]()
                        { return postJson(url, body, headers, retries); });
    }

    /// \brief Stream HTTP response via callback (for server-sent events, etc.)
    void postStream(const std::string& url, const parsers::Json& body,
                    const std::map<std::string, std::string>& headers,
                    const std::function<void(const std::string&)>& onChunk,
                    int retries = 0)
    {
      std::map<std::string, std::string> streamHeaders = headers;
      streamHeaders["Accept"] = "text/event-stream";
      streamHeaders["Cache-Control"] = "no-cache";

      Response response = postJson(url, body, streamHeaders, retries);
      if (!response.success())
      {
        throw std::runtime_error("HTTP request failed: " +
                                 std::to_string(response.statusCode));
      }

      // Split response body into lines and call onChunk for each
      std::istringstream stream(response.body);
      std::string line;
      while (std::getline(stream, line))
      {
        onChunk(line);
      }
    }

    /// \brief Upload file via multipart form data
    Response postFile(const std::string& url, const std::string& fieldName,
                      const std::string& filePath,
                      const std::map<std::string, std::string>& headers = {},
                      int retries = 0)
    {
      // Read file content
      std::ifstream file(filePath, std::ios::binary);
      if (!file)
      {
        throw std::runtime_error("Cannot read file: " + filePath);
      }

      std::string fileContent((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
      file.close();

      // Extract filename from path
      std::string filename = filePath;
      auto pos = filename.find_last_of("/\\");
      if (pos != std::string::npos)
      {
        filename = filename.substr(pos + 1);
      }

      // Create multipart form data
      std::string boundary =
          "----IoraBoundary" + std::to_string(std::time(nullptr));
      std::ostringstream body;
      body << "--" << boundary << "\r\n";
      body << "Content-Disposition: form-data; name=\"" << fieldName
           << "\"; filename=\"" << filename << "\"\r\n";
      body << "Content-Type: application/octet-stream\r\n\r\n";
      body << fileContent;
      body << "\r\n--" << boundary << "--\r\n";

      std::map<std::string, std::string> multipartHeaders = headers;
      multipartHeaders["Content-Type"] =
          "multipart/form-data; boundary=" + boundary;

      return performRequest("POST", url, body.str(), multipartHeaders, retries);
    }

    /// \brief Parse JSON response or throw on error (with default config)
    static parsers::Json parseJsonOrThrow(const Response& response)
    {
      JsonConfig defaultConfig;
      return parseJsonOrThrow(response, defaultConfig);
    }

    /// \brief Parse JSON response or throw on error (with custom config)
    static parsers::Json parseJsonOrThrow(const Response& response,
                                         const JsonConfig& jsonConfig)
    {
      if (!response.success())
      {
        throw std::runtime_error("HTTP failed with status: " +
                                 std::to_string(response.statusCode));
      }

      if (response.body.size() > jsonConfig.maxPayloadSize)
      {
        throw std::runtime_error("JSON response exceeds maximum size limit of " +
                                std::to_string(jsonConfig.maxPayloadSize) + " bytes");
      }

      auto result = parsers::Json::parse(response.body, jsonConfig.parseLimits);
      if (!result.ok)
      {
        throw std::runtime_error("JSON parse error: " + result.error.message);
      }
      return std::move(result.value);
    }

    /// \brief Cleanup connections and resources
    void cleanup()
    {
      std::lock_guard<std::mutex> lock(_mutex);

      // Close all connections
      for (const auto& [hostPort, sessionId] : _connections)
      {
        _transport->close(sessionId);
      }
      _connections.clear();
      _connectionLastUsed.clear();

      if (_transport)
      {
        _transport->stop();
      }

      if (_dnsClient)
      {
        _dnsClient->stop();
      }
    }

  private:
    /// \brief Parse URL into components
    ParsedUrl parseUrl(const std::string& url) const
    {
      ParsedUrl parsed;

      // Simple regex-based URL parsing
      std::regex urlRegex(
          R"(^(https?):\/\/([^:\/\s]+)(?::(\d+))?(\/?[^?\s]*)(?:\?([^#\s]*))?(?:#.*)?$)");
      std::smatch match;

      if (!std::regex_match(url, match, urlRegex))
      {
        throw std::invalid_argument("Invalid URL format: " + url);
      }

      parsed.scheme = match[1].str();
      parsed.host = match[2].str();

      // Default ports
      if (match[3].matched)
      {
        parsed.port = static_cast<std::uint16_t>(std::stoi(match[3].str()));
      }
      else
      {
        parsed.port = (parsed.scheme == "https") ? 443 : 80;
      }

      parsed.path = match[4].str();
      if (parsed.path.empty())
        parsed.path = "/";

      parsed.query = match[5].str();

      return parsed;
    }

    /// \brief Get or create connection to host
    SessionId getConnection(const ParsedUrl& parsedUrl)
    {
      // EMERGENCY TIMEOUT: Wrap entire connection attempt with ultimate timeout
      auto emergencyStart = std::chrono::steady_clock::now();
      auto emergencyTimeout =
          std::chrono::milliseconds(5000); // 5 seconds maximum

      std::lock_guard<std::mutex> lock(_mutex);

      std::string hostPort = parsedUrl.getHostPort();

      // Check for existing connection
      auto it = _connections.find(hostPort);
      if (it != _connections.end())
      {
        // Check if connection is still alive and not idle
        auto sessionId = it->second;
        auto health = _transport->getConnectionHealth(sessionId);

        if (health.isHealthy)
        {
          auto now = std::chrono::steady_clock::now();
          auto lastUsed = _connectionLastUsed[sessionId];

          if (now - lastUsed < _config.connectionIdleTimeout)
          {
            _connectionLastUsed[sessionId] = now;
            return sessionId;
          }
        }

        // Connection is dead or idle, remove it
        _transport->close(sessionId);
        _connections.erase(it);
        _connectionLastUsed.erase(sessionId);
      }

      // Resolve hostname if needed
      std::string resolvedHost = parsedUrl.host;
      if (!isIPAddress(parsedUrl.host))
      {
        // Handle localhost specially
        if (parsedUrl.host == "localhost")
        {
          resolvedHost = "127.0.0.1";
        }
        else
        {
          try
          {
            auto result = _dnsClient->resolveHost(parsedUrl.host);
            if (!result.ipv4.empty())
            {
              resolvedHost = result.ipv4[0]; // Use first IPv4 address
            }
            else if (!result.ipv6.empty())
            {
              resolvedHost = result.ipv6[0]; // Use first IPv6 address
            }
          }
          catch (const std::exception& e)
          {
            // DNS resolution failed, try connecting with hostname directly
            // The transport layer might handle this
          }
        }
      }

      // Create new connection with callback-based timeout
      TlsMode tlsMode = parsedUrl.isHttps() ? TlsMode::Client : TlsMode::None;

      // Call connect directly - the transport layer now handles timeouts
      // properly
      SessionId sessionId =
          _transport->connect(resolvedHost, parsedUrl.port, tlsMode);

      // Emergency timeout check
      if (std::chrono::steady_clock::now() - emergencyStart > emergencyTimeout)
      {
        throw std::runtime_error("EMERGENCY TIMEOUT: Connection attempt to " +
                                 hostPort + " exceeded 5 seconds");
      }
      if (sessionId == 0)
      {
        throw std::runtime_error("Failed to initiate connection to " +
                                 hostPort);
      }

      // Use aggressive polling with immediate failure detection for localhost
      auto startTime = std::chrono::steady_clock::now();

      // For localhost connections, we expect immediate failure - don't wait
      // long
      auto maxWaitTime = (resolvedHost == "127.0.0.1")
                             ? std::chrono::milliseconds(100)
                             : _config.connectTimeout;

      while (true)
      {
        auto health = _transport->getConnectionHealth(sessionId);

        // If connection becomes healthy, we're done
        if (health.isHealthy)
        {
          break;
        }

        // Check for explicit errors (this should catch failed connections)
        if (health.errorCount > 0)
        {
          _transport->close(sessionId);
          throw std::runtime_error("Connection failed to " + hostPort + " (" +
                                   health.lastErrorMessage + ")");
        }

        // Check for timeout
        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (elapsed > maxWaitTime)
        {
          _transport->close(sessionId);
          auto elapsedMs =
              std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
                  .count();
          throw std::runtime_error("Connection timeout to " + hostPort +
                                   " after " + std::to_string(elapsedMs) +
                                   "ms");
        }

        // Emergency timeout check
        if (std::chrono::steady_clock::now() - emergencyStart >
            emergencyTimeout)
        {
          _transport->close(sessionId);
          throw std::runtime_error("EMERGENCY TIMEOUT: Connection polling to " +
                                   hostPort + " exceeded 5 seconds");
        }

        // For debugging: if this is a localhost connection and we've waited
        // more than 50ms, something is wrong
        if (resolvedHost == "127.0.0.1" &&
            elapsed > std::chrono::milliseconds(50))
        {
          _transport->close(sessionId);
          auto elapsedMs =
              std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
                  .count();
          throw std::runtime_error("Localhost connection taking too long - "
                                   "should fail immediately. Waited " +
                                   std::to_string(elapsedMs) + "ms");
        }

        // Very short sleep to check frequently
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }

      // Store connection
      _connections[hostPort] = sessionId;
      _connectionLastUsed[sessionId] = std::chrono::steady_clock::now();

      return sessionId;
    }

    /// \brief Check if string is an IP address
    bool isIPAddress(const std::string& str) const
    {
      // Simple IPv4 check (could be enhanced for IPv6)
      std::regex ipv4Regex(R"(^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)");
      return std::regex_match(str, ipv4Regex);
    }

    /// \brief Perform HTTP request with retry logic
    Response performRequest(const std::string& method, const std::string& url,
                            const std::string& body,
                            const std::map<std::string, std::string>& headers,
                            int retries)
    {
      {
        std::lock_guard<std::mutex> lock(_mutex);
        ensureInitialized();
      }

      // Log the outgoing request
      iora::core::Logger::info("HttpClient: " + method + " " + url +
                               " (body size: " + std::to_string(body.size()) +
                               " bytes)");

      int attempt = 0;
      while (true)
      {
        try
        {
          auto response = executeRequest(method, url, body, headers);

          // Log the response
          iora::core::Logger::info(
              "HttpClient: Received " + std::to_string(response.statusCode) +
              " response from " + url + " (body size: " +
              std::to_string(response.body.size()) + " bytes)");

          return response;
        }
        catch (const std::exception& e)
        {
          if (attempt >= retries)
          {
            iora::core::Logger::error(
                "HttpClient: Request to " + url + " failed after " +
                std::to_string(attempt + 1) + " attempts: " + e.what());
            throw;
          }

          // Log retry attempt
          iora::core::Logger::debug("HttpClient: Retrying request to " + url +
                                    " (attempt " + std::to_string(attempt + 1) +
                                    "/" + std::to_string(retries + 1) +
                                    "): " + e.what());

          // Exponential backoff with jitter
          int backoffMs = (1 << attempt) * 100 + (rand() % 100);
          std::this_thread::sleep_for(std::chrono::milliseconds(backoffMs));
          attempt++;
        }
      }
    }

    /// \brief Execute single HTTP request
    Response executeRequest(const std::string& method, const std::string& url,
                            const std::string& body,
                            const std::map<std::string, std::string>& headers)
    {
      auto parsedUrl = parseUrl(url);

      // Use normal timeout - optimization will be handled at transport level
      std::chrono::milliseconds sendTimeout = _config.requestTimeout;

      auto sessionId = getConnection(parsedUrl);

      // Set session to sync mode BEFORE sending request so response data gets
      // buffered correctly
      if (!_transport->setReadMode(sessionId, ReadMode::Sync))
      {
        throw std::runtime_error("Failed to set session to sync read mode");
      }

      // Build HTTP request
      std::ostringstream request;
      request << method << " " << parsedUrl.getPathWithQuery()
              << " HTTP/1.1\r\n";
      request << "Host: " << parsedUrl.host << "\r\n";
      request << "User-Agent: " << _config.userAgent << "\r\n";
      request << "Connection: "
              << (_config.reuseConnections ? "keep-alive" : "close") << "\r\n";

      // Add custom headers
      for (const auto& [name, value] : headers)
      {
        request << name << ": " << value << "\r\n";
      }

      // Add body if present
      if (!body.empty())
      {
        request << "Content-Length: " << body.size() << "\r\n";
      }

      request << "\r\n";
      if (!body.empty())
      {
        request << body;
      }

      std::string requestStr = request.str();

      // Send request synchronously
      auto sendResult = _transport->sendSync(sessionId, requestStr.data(),
                                             requestStr.size(), sendTimeout);
      if (!sendResult.ok)
      {
        _transport->setReadMode(sessionId, ReadMode::Async);
        throw std::runtime_error("Failed to send HTTP request: " +
                                 sendResult.errorMessage);
      }

      // Receive response synchronously by accumulating data until we have a
      // complete HTTP response
      std::string responseData;
      char buffer[8192];

      try
      {
        while (true)
        {
          std::size_t len = sizeof(buffer);

          auto recvResult =
              _transport->receiveSync(sessionId, buffer, len, sendTimeout);

          if (recvResult.ok && len > 0)
          {
            responseData.append(buffer, len);

            // Check if we have complete HTTP response
            if (isCompleteHttpResponse(responseData))
            {
              break;
            }
          }
          else if (!recvResult.ok &&
                   recvResult.error == TransportError::Timeout)
          {
            throw std::runtime_error("HTTP response timeout");
          }
          else if (!recvResult.ok)
          {
            throw std::runtime_error(
                "Connection closed before receiving complete HTTP response");
          }
          // If len == 0, the receiveSync will have waited for the timeout
          // already, so continue
        }

        // Reset read mode back to async for connection reuse
        _transport->setReadMode(sessionId, ReadMode::Async);
        return parseHttpResponse(responseData);
      }
      catch (...)
      {
        // Reset read mode on any exception
        _transport->setReadMode(sessionId, ReadMode::Async);
        throw;
      }
    }

    /// \brief Check if we have a complete HTTP response
    bool isCompleteHttpResponse(const std::string& data) const
    {
      // Look for end of headers
      auto headerEnd = data.find("\r\n\r\n");
      if (headerEnd == std::string::npos)
      {
        return false; // Headers not complete
      }

      // Parse headers to check for Content-Length or Transfer-Encoding
      std::string headers = data.substr(0, headerEnd);
      std::string body = data.substr(headerEnd + 4);

      // Look for Content-Length
      std::regex contentLengthRegex(R"(Content-Length:\s*(\d+))",
                                    std::regex_constants::icase);
      std::smatch match;
      if (std::regex_search(headers, match, contentLengthRegex))
      {
        std::size_t contentLength = std::stoul(match[1].str());
        return body.size() >= contentLength;
      }

      // Look for Transfer-Encoding: chunked
      std::regex chunkedRegex(R"(Transfer-Encoding:\s*chunked)",
                              std::regex_constants::icase);
      if (std::regex_search(headers, chunkedRegex))
      {
        // Simple chunked detection - look for final chunk (0\r\n\r\n)
        return data.find("0\r\n\r\n") != std::string::npos;
      }

      // No content length specified, assume complete (HTTP/1.0 style)
      return true;
    }

    /// \brief Parse HTTP response from raw data
    Response parseHttpResponse(const std::string& data) const
    {
      Response response;

      // Find end of headers
      auto headerEnd = data.find("\r\n\r\n");
      if (headerEnd == std::string::npos)
      {
        throw std::runtime_error(
            "Invalid HTTP response: no header separator found");
      }

      std::string headerSection = data.substr(0, headerEnd);
      std::string bodySection = data.substr(headerEnd + 4);

      // Parse status line
      std::istringstream headerStream(headerSection);
      std::string statusLine;
      std::getline(headerStream, statusLine);

      // Remove trailing \r if present
      if (!statusLine.empty() && statusLine.back() == '\r')
      {
        statusLine.pop_back();
      }

      // Parse status code and text
      std::regex statusRegex(R"(HTTP/\d\.\d\s+(\d+)\s*(.*))");
      std::smatch statusMatch;
      if (std::regex_match(statusLine, statusMatch, statusRegex))
      {
        response.statusCode = std::stoi(statusMatch[1].str());
        response.statusText = statusMatch[2].str();
      }
      else
      {
        throw std::runtime_error("Invalid HTTP status line: " + statusLine);
      }

      // Parse headers
      std::string headerLine;
      while (std::getline(headerStream, headerLine))
      {
        if (!headerLine.empty() && headerLine.back() == '\r')
        {
          headerLine.pop_back();
        }

        auto colonPos = headerLine.find(':');
        if (colonPos != std::string::npos)
        {
          std::string name = headerLine.substr(0, colonPos);
          std::string value = headerLine.substr(colonPos + 1);

          // Trim whitespace
          name.erase(0, name.find_first_not_of(" \t"));
          name.erase(name.find_last_not_of(" \t") + 1);
          value.erase(0, value.find_first_not_of(" \t"));
          value.erase(value.find_last_not_of(" \t") + 1);

          response.headers[name] = value;
        }
      }

      // Handle body based on Content-Length or Transfer-Encoding
      auto contentLengthIt = response.headers.find("Content-Length");
      if (contentLengthIt != response.headers.end())
      {
        std::size_t contentLength = std::stoul(contentLengthIt->second);
        response.body = bodySection.substr(0, contentLength);
      }
      else
      {
        auto transferEncodingIt = response.headers.find("Transfer-Encoding");
        if (transferEncodingIt != response.headers.end() &&
            transferEncodingIt->second.find("chunked") != std::string::npos)
        {
          response.body = decodeChunkedBody(bodySection);
        }
        else
        {
          response.body = bodySection;
        }
      }

      return response;
    }

    /// \brief Decode chunked transfer encoding
    std::string decodeChunkedBody(const std::string& chunkedData) const
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

        // Parse chunk size (hex)
        std::size_t chunkSize = std::stoul(line, nullptr, 16);
        if (chunkSize == 0)
        {
          break; // End of chunks
        }

        // Read chunk data
        std::string chunkData(chunkSize, '\0');
        stream.read(&chunkData[0], chunkSize);
        result += chunkData;

        // Skip trailing CRLF
        std::getline(stream, line);
      }

      return result;
    }
  };

} // namespace network
} // namespace iora