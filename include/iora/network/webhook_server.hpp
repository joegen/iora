#pragma once
#include <iostream>
#include <stdexcept>
#include <string>
#include <mutex>
#include <unordered_map>
#include <optional>
#include <chrono>
#include <functional>
#include <variant>

#include <httplib.h>
#include "iora/core/json.hpp"

namespace iora {
namespace network {
  

  /// \brief Lightweight, testable HTTP webhook server for handling REST and
  /// JSON endpoints.
  class WebhookServer
  {
  public:
    /// \brief Explicitly delete copy/move constructors and assignment operators
    WebhookServer(const WebhookServer&) = delete;
    WebhookServer& operator=(const WebhookServer&) = delete;
    WebhookServer(WebhookServer&&) = delete;
    WebhookServer& operator=(WebhookServer&&) = delete;

    /// \brief TLS configuration for the server
    struct TlsConfig
    {
      std::string certFile;
      std::string keyFile;
      std::string caFile;
      bool requireClientCert = false;
    };

    using Handler =
        std::function<void(const httplib::Request&, httplib::Response&)>;
    using JsonHandler = std::function<core::Json(const core::Json&)>;

    static constexpr int DEFAULT_PORT = 8080;

    /// \brief Constructs a WebhookServer with the default port.
    WebhookServer() : _port(DEFAULT_PORT) {}

    ~WebhookServer()
    {
      try
      {
        stop();
      }
      catch (const std::exception& e)
      {
        // Log the error but don't throw from destructor
        iora::core::Logger::error("WebhookServer destructor error: " +
                                 std::string(e.what()));
      }
      catch (...)
      {
        // Handle any other exceptions
        iora::core::Logger::error("WebhookServer destructor unknown error");
      }
    }

    /// \brief Sets the port for the server.
    void setPort(int port)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _port = port;
    }

    /// \brief Enables TLS with the given configuration. Throws if cert/key
    /// files are missing.
    void enableTls(const TlsConfig& config)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      // Validate cert/key files exist
      if (config.certFile.empty() || config.keyFile.empty())
      {
        throw std::runtime_error("TLS: certFile and keyFile must be set");
      }
      std::ifstream certTest(config.certFile);
      std::ifstream keyTest(config.keyFile);
      if (!certTest.good() || !keyTest.good())
      {
        throw std::runtime_error("TLS: certFile or keyFile not readable");
      }
      if (config.requireClientCert && config.caFile.empty())
      {
        throw std::runtime_error(
            "TLS: requireClientCert is true but caFile is not set");
      }
      if (config.requireClientCert)
      {
        std::ifstream caTest(config.caFile);
        if (!caTest.good())
        {
          throw std::runtime_error("TLS: caFile not readable");
        }
      }
      _tlsConfig = config;
    }

    /// \brief Registers a GET handler for the given path.
    void onGet(const std::string& path, Handler handler)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (isServerActiveLocked())
      {
        withActiveServerLocked(
            [&](auto& server)
            { server.Get(path.c_str(), std::move(handler)); });
      }
      else
      {
        _pendingGetHandlers.emplace_back(path, std::move(handler));
      }
    }

    /// \brief Registers a GET handler for JSON endpoints.
    void onJsonGet(const std::string& endpoint, JsonHandler handler)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (isServerActiveLocked())
      {
        withActiveServerLocked(
            [&](auto& server)
            {
              server.Get(
                  endpoint.c_str(),
                  [handler = std::move(handler)](const httplib::Request& req,
                                                 httplib::Response& res)
                  {
                    try
                    {
                      core::Json requestJson =
                          util::SafeJsonParser::parseWithLimits(req.body);
                      core::Json responseJson = handler(requestJson);
                      res.set_content(responseJson.dump(), "application/json");
                    }
                    catch (const std::exception& ex)
                    {
                      res.status = 500;
                      res.set_content(ex.what(), "text/plain");
                      iora::core::Logger::error(
                          std::string(
                              "WebhookServer onJsonGet handler error: ") +
                          ex.what());
                    }
                  });
            });
      }
      else
      {
        _pendingJsonGetHandlers.emplace_back(endpoint, std::move(handler));
      }
    }

    /// \brief Registers a POST handler for the given path.
    void onPost(const std::string& path, Handler handler)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (isServerActiveLocked())
      {
        withActiveServerLocked(
            [&](auto& server)
            { server.Post(path.c_str(), std::move(handler)); });
      }
      else
      {
        _pendingPostHandlers.emplace_back(path, std::move(handler));
      }
    }

    /// \brief Registers a POST handler for JSON endpoints.
    void onJsonPost(const std::string& endpoint, JsonHandler handler)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (isServerActiveLocked())
      {
        withActiveServerLocked(
            [&](auto& server)
            {
              server.Post(
                  endpoint.c_str(),
                  [handler = std::move(handler)](const httplib::Request& req,
                                                 httplib::Response& res)
                  {
                    try
                    {
                      core::Json requestJson =
                          util::SafeJsonParser::parseWithLimits(req.body);
                      core::Json responseJson = handler(requestJson);
                      res.set_content(responseJson.dump(), "application/json");
                    }
                    catch (const std::exception& ex)
                    {
                      res.status = 500;
                      res.set_content(ex.what(), "text/plain");
                      iora::core::Logger::error(
                          std::string(
                              "WebhookServer onJsonPost handler error: ") +
                          ex.what());
                    }
                  });
            });
      }
      else
      {
        _pendingJsonPostHandlers.emplace_back(endpoint, std::move(handler));
      }
    }

    /// \brief Registers a DELETE handler for the given path.
    void onDelete(const std::string& path, Handler handler)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (isServerActiveLocked())
      {
        withActiveServerLocked(
            [&](auto& server)
            { server.Delete(path.c_str(), std::move(handler)); });
      }
      else
      {
        _pendingDeleteHandlers.emplace_back(path, std::move(handler));
      }
    }

    /// \brief Starts the server. Throws on error.
    void start()
    {
      std::lock_guard<std::mutex> lock(_mutex);
      try
      {
        if (_tlsConfig.has_value())
        {
          const auto& cfg = _tlsConfig.value();
          _server.emplace<httplib::SSLServer>(
              cfg.certFile.c_str(), cfg.keyFile.c_str(),
              cfg.caFile.empty() ? nullptr : cfg.caFile.c_str());
          auto& ssl = std::get<httplib::SSLServer>(_server);
          bindHandlersLocked(ssl);
          _thread.emplace(
              [this]() {
                std::get<httplib::SSLServer>(_server).listen("0.0.0.0", _port);
              });
        }
        else
        {
          _server.emplace<httplib::Server>();
          auto& server = std::get<httplib::Server>(_server);
          bindHandlersLocked(server);
          _thread.emplace(
              [this]()
              { std::get<httplib::Server>(_server).listen("0.0.0.0", _port); });
        }
      }
      catch (const std::exception& ex)
      {
        iora::core::Logger::error(std::string("WebhookServer start error: ") +
                                 ex.what());
        throw;
      }
    }

    /// \brief Stops the server and joins the thread if needed.
    void stop()
    {
      std::lock_guard<std::mutex> lock(_mutex);
      std::visit(
          [](auto& s)
          {
            using T = std::decay_t<decltype(s)>;
            if constexpr (!std::is_same_v<T, std::monostate>)
            {
              s.stop();
            }
          },
          _server);
      if (_thread && _thread->joinable() &&
          std::this_thread::get_id() != _thread->get_id())
      {
        _thread->join();
      }
      _thread.reset();
    }

  private:
    /// \brief Returns true if the server is active (not monostate).
    [[nodiscard]] bool isServerActiveLocked() const
    {
      return _server.index() != 0;
    }

    /// \brief Calls the given function with the active server instance.
    template <typename F> void withActiveServerLocked(F&& f)
    {
      std::visit(
          [&](auto& s)
          {
            using T = std::decay_t<decltype(s)>;
            if constexpr (!std::is_same_v<T, std::monostate>)
            {
              f(s);
            }
          },
          _server);
    }

    /// \brief Configures server security settings.
    template <typename ServerT> void configureServerSecurity(ServerT& server)
    {
      // Set timeouts and limits for security
      server.set_read_timeout(30, 0);      // 30 seconds read timeout
      server.set_write_timeout(30, 0);     // 30 seconds write timeout
      server.set_keep_alive_max_count(10); // Limit keep-alive connections
      server.set_payload_max_length(10 * 1024 * 1024); // 10MB max payload
    }

    /// \brief Binds all pending handlers to the given server instance.
    template <typename ServerT> void bindHandlersLocked(ServerT& server)
    {
      configureServerSecurity(server);
      for (auto& [path, handler] : _pendingPostHandlers)
      {
        server.Post(path.c_str(), std::move(handler));
      }
      for (auto& [path, handler] : _pendingGetHandlers)
      {
        server.Get(path.c_str(), std::move(handler));
      }
      for (auto& [path, handler] : _pendingJsonGetHandlers)
      {
        server.Get(
            path.c_str(),
            [handler = std::move(handler)](const httplib::Request& req,
                                           httplib::Response& res)
            {
              try
              {
                core::Json requestJson =
                    util::SafeJsonParser::parseWithLimits(req.body);
                core::Json responseJson = handler(requestJson);
                res.set_content(responseJson.dump(), "application/json");
              }
              catch (const std::exception& ex)
              {
                res.status = 500;
                res.set_content(ex.what(), "text/plain");
                iora::core::Logger::error(
                    std::string(
                        "WebhookServer bindHandlersLocked onJsonGet error: ") +
                    ex.what());
              }
            });
      }
      for (auto& [path, handler] : _pendingJsonPostHandlers)
      {
        server.Post(
            path.c_str(),
            [handler = std::move(handler)](const httplib::Request& req,
                                           httplib::Response& res)
            {
              try
              {
                core::Json requestJson =
                    util::SafeJsonParser::parseWithLimits(req.body);
                core::Json responseJson = handler(requestJson);
                res.set_content(responseJson.dump(), "application/json");
              }
              catch (const std::exception& ex)
              {
                res.status = 500;
                res.set_content(ex.what(), "text/plain");
                iora::core::Logger::error(
                    std::string(
                        "WebhookServer bindHandlersLocked onJsonPost error: ") +
                    ex.what());
              }
            });
      }
      _pendingPostHandlers.clear();
      _pendingGetHandlers.clear();
      _pendingJsonGetHandlers.clear();
      _pendingJsonPostHandlers.clear();
    }

    mutable std::mutex _mutex;

    int _port;
    std::optional<TlsConfig> _tlsConfig;
    std::variant<std::monostate, httplib::Server, httplib::SSLServer> _server;
    std::optional<std::thread> _thread;

    std::vector<std::pair<std::string, Handler>> _pendingPostHandlers;
    std::vector<std::pair<std::string, Handler>> _pendingGetHandlers;
    std::vector<std::pair<std::string, Handler>> _pendingDeleteHandlers;
    std::vector<std::pair<std::string, JsonHandler>> _pendingJsonGetHandlers;
    std::vector<std::pair<std::string, JsonHandler>> _pendingJsonPostHandlers;
  };

} } // namespace iora::network