// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <mutex>
#include <unordered_map>
#include <optional>
#include <chrono>

#include <cpr/cpr.h>
#include "iora/core/json.hpp"

namespace iora {
namespace network {
  /// \brief Feature-rich HTTP client supporting synchronous, asynchronous, and
  /// streaming API calls.
  class HttpClient
  {
  public:
   /// \brief TLS configuration for HTTPS requests.
    struct TlsConfig
    {
      std::string caFile;
      std::string clientCertFile;
      std::string clientKeyFile;
      bool verifyPeer = true;
    };

    /// \brief Performs a GET request with optional headers. Detects scheme and applies TLS config for HTTPS.
    core::Json get(const std::string& url,
                   const std::map<std::string, std::string>& headers = {},
                   int retries = 0) const
    {
      bool isHttps = url.find("https://") == 0;
      if (isHttps)
      {
        auto ssl = getValidatedSslOptions();
        return retry(
            [&]()
            {
              return cpr::Get(cpr::Url{url},
                              cpr::Header{headers.begin(), headers.end()},
                              ssl);
            },
            retries);
      }
      else
      {
        return retry(
            [&]()
            {
              return cpr::Get(cpr::Url{url},
                              cpr::Header{headers.begin(), headers.end()});
            },
            retries);
      }
    }

    /// \brief Performs a POST request with JSON payload. Detects scheme and applies TLS config for HTTPS.
    core::Json postJson(const std::string& url, const core::Json& body,
                        const std::map<std::string, std::string>& headers = {},
                        int retries = 0) const
    {
      auto allHeaders = headers;
      allHeaders.emplace("Content-Type", "application/json");
      bool isHttps = url.find("https://") == 0;
      if (isHttps)
      {
        auto ssl = getValidatedSslOptions();
        return retry(
            [&]()
            {
              return cpr::Post(cpr::Url{url}, cpr::Body{body.dump()},
                               cpr::Header{allHeaders.begin(), allHeaders.end()},
                               ssl);
            },
            retries);
      }
      else
      {
        return retry(
            [&]()
            {
              return cpr::Post(cpr::Url{url}, cpr::Body{body.dump()},
                               cpr::Header{allHeaders.begin(), allHeaders.end()});
            },
            retries);
      }
    }

    /// \brief Performs a POST request with multipart form-data. Detects scheme and applies TLS config for HTTPS.
    core::Json
    postSingleFile(const std::string& url, const std::string& fileFieldName,
                   const std::string& filePath,
                   const std::map<std::string, std::string>& headers = {},
                   int retries = 0) const
    {
      cpr::Multipart multipart{
          cpr::Part{fileFieldName, filePath, "application/octet-stream"}};
      bool isHttps = url.find("https://") == 0;
      if (isHttps)
      {
        auto ssl = getValidatedSslOptions();
        return retry(
            [&]()
            {
              return cpr::Post(cpr::Url{url}, multipart,
                               cpr::Header{headers.begin(), headers.end()},
                               ssl);
            },
            retries);
      }
      else
      {
        return retry(
            [&]()
            {
              return cpr::Post(cpr::Url{url}, multipart,
                               cpr::Header{headers.begin(), headers.end()});
            },
            retries);
      }
    }


    /// \brief Performs a DELETE request.
    core::Json
    deleteRequest(const std::string& url,
                  const std::map<std::string, std::string>& headers = {},
                  int retries = 0) const
    {
      bool isHttps = url.find("https://") == 0;
      if (isHttps)
      {
        auto ssl = getValidatedSslOptions();
        return retry(
            [&]()
            {
              return cpr::Delete(cpr::Url{url},
                               cpr::Header{headers.begin(), headers.end()},
                               ssl);
            },
            retries);
      }
      else
      {
        return retry(
            [&]()
            {
              return cpr::Delete(cpr::Url{url},
                                cpr::Header{headers.begin(), headers.end()});
            },
            retries);
          }
    }

    /// \brief Performs a POST request asynchronously using std::future.
    std::future<core::Json>
    postJsonAsync(const std::string& url, const core::Json& body,
                  const std::map<std::string, std::string>& headers = {},
                  int retries = 0) const
    {
      return std::async(std::launch::async, [=]()
                        { return postJson(url, body, headers, retries); });
    }

    /// \brief Performs a POST request and streams line-delimited responses via
    /// callback.
    void postStream(const std::string& url, const core::Json& body,
                    const std::map<std::string, std::string>& headers,
                    const std::function<void(const std::string&)>& onChunk,
                    int retries = 0) const
    {
      cpr::Response response;
      bool isHttps = url.find("https://") == 0;
      if (isHttps)
      {
        auto ssl = getValidatedSslOptions();
        response = cpr::Post(cpr::Url{url}, cpr::Body{body.dump()},
                             cpr::Header{headers.begin(), headers.end()},
                             cpr::Header{{"Accept", "text/event-stream"}},
                             ssl);
      }
      else
      {
        response = cpr::Post(cpr::Url{url}, cpr::Body{body.dump()},
                      cpr::Header{headers.begin(), headers.end()},
                      cpr::Header{{"Accept", "text/event-stream"}});
      }

      std::istringstream stream(response.text);
      std::string line;
      while (std::getline(stream, line))
      {
        onChunk(line);
      }
    }

    /// \brief Parses the response as JSON or throws.
    static core::Json parseJsonOrThrow(const cpr::Response& response)
    {
      if (response.status_code < 200 || response.status_code >= 300)
      {
        throw std::runtime_error("HTTP failed with status: " +
                                 std::to_string(response.status_code));
      }

      try
      {
        return util::SafeJsonParser::parseWithLimits(response.text);
      }
      catch (const std::exception& e)
      {
        throw std::runtime_error("Invalid JSON: " + std::string(e.what()));
      }
    }

    /// \brief Returns raw text body from a cpr::Response.
    static std::string getRawBody(const cpr::Response& response)
    {
      return response.text;
    }

    /// \brief Estimates token count based on approximate word-to-token ratio.
    static int estimateTokenCount(const std::string& text)
    {
      int wordCount = 0;
      std::istringstream iss(text);
      std::string token;
      while (iss >> token)
      {
        wordCount++;
      }
      return static_cast<int>(wordCount *
                              1.5); // Estimated ~1.5 tokens per word
    }

    /// \brief Sets the TLS configuration for HTTPS requests.
    void setTlsConfig(const TlsConfig& config)
    {
      std::lock_guard<std::mutex> lock(_tlsMutex);
      _tlsConfig = config;
    }


  private:
    template <typename Callable>
    core::Json retry(Callable&& action, int retries) const
    {
      int attempt = 0;
      while (true)
      {
        cpr::Response response = action();

        if (response.status_code >= 200 && response.status_code < 300)
        {
          return parseJsonOrThrow(response);
        }

        if (attempt >= retries)
        {
          throw std::runtime_error("HTTP request failed after retries: " +
                                   std::to_string(response.status_code));
        }

        int backoffMs = (1 << attempt) * 100 + rand() % 100;
        std::this_thread::sleep_for(std::chrono::milliseconds(backoffMs));
        attempt++;
      }
    }

    /// \brief Validates TLS config and constructs cpr::SslOptions. Throws if invalid.
    cpr::SslOptions getValidatedSslOptions() const
    {
      std::lock_guard<std::mutex> lock(_tlsMutex);
      namespace fs = std::filesystem;
      if (_tlsConfig.verifyPeer && _tlsConfig.caFile.empty())
      {
        throw std::runtime_error("TLS: CA file must be set for peer verification");
      }
      if (!_tlsConfig.clientCertFile.empty() && !fs::exists(_tlsConfig.clientCertFile))
      {
        throw std::runtime_error("TLS: clientCertFile does not exist");
      }
      if (!_tlsConfig.clientKeyFile.empty() && !fs::exists(_tlsConfig.clientKeyFile))
      {
        throw std::runtime_error("TLS: clientKeyFile does not exist");
      }
      if (_tlsConfig.verifyPeer && !_tlsConfig.caFile.empty() && !fs::exists(_tlsConfig.caFile))
      {
        throw std::runtime_error("TLS: caFile does not exist");
      }
      cpr::SslOptions ssl;
      if (!_tlsConfig.caFile.empty())
      {
        ssl.ca_info = _tlsConfig.caFile;
      }
      if (!_tlsConfig.clientCertFile.empty())
      {
        ssl.cert_file = _tlsConfig.clientCertFile;
      }
      if (!_tlsConfig.clientKeyFile.empty())
      {
        ssl.key_file = _tlsConfig.clientKeyFile;
      }
      // If CPR supports verify, set it:
      ssl.verify_peer = _tlsConfig.verifyPeer;
      return ssl;
    }

    mutable std::mutex _tlsMutex;
    TlsConfig _tlsConfig;
  };
} } // namespace iora::network