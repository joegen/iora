// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include "core/json.hpp"
#include "core/logger.hpp"
#include "core/config_loader.hpp"
#include "core/thread_pool.hpp"
#include "util/safe_json_parser.hpp"
#include "util/expiring_cache.hpp"
#include "util/event_queue.hpp"
#include "util/plugin_loader.hpp"
#include "util/tokenizer.hpp"
#include "util/filesystem.hpp"
#include "storage/concrete_state_store.hpp"
#include "storage/json_file_store.hpp"
#include "system/shell_runner.hpp"
#include "network/http_client.hpp"
#include "network/webhook_server.hpp"



namespace iora {

/// \brief Singleton entry point for the Iora library, managing all core
/// components and providing factory methods for utilities and plugins.
class IoraService : private util::PluginManager
{
public:
  /// \brief Deleted copy constructor and assignment operator.
  IoraService(const IoraService&) = delete;
  IoraService& operator=(const IoraService&) = delete;

  /// \brief Constructor initialises members and loads configuration.
  IoraService() {}

  /// \brief Destructor stops the server with proper cleanup.
  ~IoraService()
  {
    try
    {
      if (_webhookServer)
      {
        _webhookServer->stop();
      }

      if (_jsonFileStore)
      {
        _jsonFileStore->flush();
      }
    }
    catch (const std::exception& e)
    {
      // Log but don't throw from destructor
      core::Logger::error("IoraService destructor error: " +
                         std::string(e.what()));
    }
    catch (...)
    {
      core::Logger::error("IoraService destructor unknown error");
    }
  }

  static IoraService& instance()
  {
    auto& ptr = instancePtr();
    if (!ptr)
    {
      throw std::runtime_error("IoraService instance has been destroyed");
    }
    return *ptr;
  }

  /// \brief Holds all configuration options for IoraService, reflecting the
  /// nested TOML structure.
  struct Config
  {
    struct ServerConfig
    {
      std::optional<int> port;
      struct TlsConfig
      {
        std::optional<std::string> certFile;
        std::optional<std::string> keyFile;
        std::optional<std::string> caFile;
        std::optional<bool> requireClientCert;
      } tls;
    } server;
    struct ModulesConfig
    {
      std::optional<std::string> directory;
      std::optional<std::vector<std::string>> modules;
    } modules;
    struct StateConfig
    {
      std::optional<std::string> file;
    } state;
    struct LogConfig
    {
      std::optional<std::string> level;
      std::optional<std::string> file;
      std::optional<bool> async;
      std::optional<int> retentionDays;
      std::optional<std::string> timeFormat;
    } log;
  };

  /// \brief Cleans up all global Iora resources, notifies plugins, and unloads
  /// shared libraries. Should be called at program exit or at the end of
  /// main().
  static void shutdown()
  {
    try
    {
      auto& instancePtr = getInstancePtr();
      if (!instancePtr)
      {
        // Already shutdown or never initialized
        return;
      }

      IoraService& svc = *instancePtr;

      svc.unloadAllModules();

      // Unload all plugin libraries
      // Flush the JSON file store
      if (svc._jsonFileStore)
      {
        svc._jsonFileStore->flush();
      }

      // Stop the webhook server if running
      if (svc._webhookServer)
      {
        svc._webhookServer->stop();
      }

      // (Optionally) clear other global resources, caches, etc.
      // Destroy unique_ptr members
      svc._webhookServer.reset();
      svc._stateStore.reset();
      svc._jsonFileStore.reset();
      svc._configLoader.reset();
      svc._cache.reset();

      svc._config = Config(); // Reset configuration
      svc._isRunning = false;

      // Flush and shutdown logger
      core::Logger::shutdown();

      // Finally, destroy the singleton instance
      IoraService::destroyInstance();
    }
    catch (const std::exception& e)
    {
      // Log error but don't propagate exception from shutdown
      try
      {
        core::Logger::error("IoraService shutdown error: " +
                           std::string(e.what()));
      }
      catch (...)
      {
        // Ignore logging errors during shutdown
      }
    }
    catch (...)
    {
      // Ignore all other exceptions during shutdown
    }
  }

  /// \brief Blocks until terminate() is called. Use to keep main() alive.
  void waitForTermination()
  {
    std::unique_lock<std::mutex> lock(_terminationMutex);
    _terminationCv.wait(lock, [this]() { return _terminated; });
  }

  /// \brief Signals termination and unblocks waitForTermination().
  void terminate()
  {
    {
      std::lock_guard<std::mutex> lock(_terminationMutex);
      _terminated = true;
    }
    _terminationCv.notify_all();
  }

  /// \brief Abstract interface all Iora plugins must implement
  class Plugin
  {
  public:
    /// \brief Constructor that sets the service instance
    explicit Plugin(IoraService* service) : _service(service)
    {
      if (!_service)
      {
        throw std::invalid_argument("IoraService instance cannot be null");
      }
    }
    virtual ~Plugin() = default;

    /// \brief Called when the plugin is loaded
    virtual void onLoad(IoraService* service) = 0;

    /// \brief Called before the plugin is unloaded
    virtual void onUnload() = 0;

    IoraService* service() const { return _service; }

  private:
    IoraService* _service = nullptr;
    std::vector<std::string> _apiExports; // APIs this plugin exports
    std::string _name;                    // Plugin name for identification
    std::string _path;                    // Path to the plugin library
    friend class IoraService; // Allow IoraService to access private members
  };

  /// \brief RAII wrapper to automatically shutdown the IoraService
  class AutoServiceShutdown
  {
  public:
    explicit AutoServiceShutdown(iora::IoraService& service) : _svc(service) {}
    ~AutoServiceShutdown() { _svc.shutdown(); }

  private:
    iora::IoraService& _svc;
  };

  /// \brief Initialises the singleton with command‑line arguments.
  ///        Supported options: `--port/-p`, `--config/-c`, `--state-file/-s`,
  ///        `--log-level/-l`, `--log-file/-f`, `--log-async`,
  ///        `--log-retention`, and `--log-time-format`.
  ///        CLI values always override the configuration file.
  static IoraService& init(int argc, char** argv)
  {
    IoraService& svc = instance();
    svc.parseConfig(argc, argv);
    return svc;
  }

  static void init(const Config& config)
  {
    IoraService& svc = instance();
    svc._config = config;
    svc.applyConfig();
  }

  /// \brief Accessor for the webhook server.
  const std::unique_ptr<network::WebhookServer>& webhookServer() const
  {
    return _webhookServer;
  }

  /// \brief Accessor for the in-memory state store.
  const std::unique_ptr<storage::ConcreteStateStore>& stateStore() const
  {
    return _stateStore;
  }

  /// \brief Accessor for the expiring cache.
  const std::unique_ptr<util::ExpiringCache<std::string, std::string>>&
  cache() const
  {
    return _cache;
  }

  /// \brief Accessor for the configuration loader.
  const std::unique_ptr<core::ConfigLoader>& configLoader() const
  {
    return _configLoader;
  }

  /// \brief Accessor for the embedded JSON file store.
  const std::unique_ptr<storage::JsonFileStore>& jsonFileStore() const
  {
    return _jsonFileStore;
  }

  /// \brief Factory for creating a JSON file store backed by the given file.
  std::unique_ptr<storage::JsonFileStore>
  makeJsonFileStore(const std::string& filename) const
  {
    return std::make_unique<storage::JsonFileStore>(filename);
  }

  /// \brief Factory for creating a new stateless HTTP client.
  network::HttpClient makeHttpClient() const { return network::HttpClient{}; }

  /// \brief Push an event to the EventQueue
  void pushEvent(const core::Json& event) { _eventQueue.push(event); }

  /// \brief Register a handler for an event by its ID
  void registerEventHandlerById(const std::string& eventId,
                                util::EventQueue::Handler handler)
  {
    _eventQueue.onEventId(eventId, std::move(handler));
  }

  /// \brief Register a handler for an event by its name
  void registerEventHandlerByName(const std::string& eventName,
                                  util::EventQueue::Handler handler)
  {
    _eventQueue.onEventName(eventName, std::move(handler));
  }

  /// \brief Provides access to the EventQueue for managing events.
  util::EventQueue& eventQueue() { return _eventQueue; }

  /// \brief Registers a plugin API function that can be called by plugins.
  template <typename Func>
  void exportApi(Plugin& plugin, const std::string& name, Func&& func)
  {
    if (name.empty())
    {
      throw std::invalid_argument("Plugin API name cannot be empty");
    }
    if (_apiExports.find(name) != _apiExports.end())
    {
      throw std::runtime_error("Plugin API already registered: " + name);
    }
    std::lock_guard<std::mutex> lock(_apiMutex);
    using func_type = std::decay_t<Func>;
    using signature = decltype(&func_type::operator());
    _apiExports[name] = makeStdFunction(std::forward<Func>(func), signature{});
    plugin._apiExports.push_back(name);
  }

  // Helper to deduce lambda signature and wrap in std::function
  template <typename Func, typename Ret, typename... Args>
  static std::function<Ret(Args...)>
  makeStdFunction(Func&& f, Ret (Func::*)(Args...) const)
  {
    return std::function<Ret(Args...)>(std::forward<Func>(f));
  }
  template <typename Func, typename Ret, typename... Args>
  static std::function<Ret(Args...)> makeStdFunction(Func&& f,
                                                     Ret (Func::*)(Args...))
  {
    return std::function<Ret(Args...)>(std::forward<Func>(f));
  }

  /// \brief Retrieves a registered plugin API as a std::function for repeated
  /// calls.
  /// Throws std::runtime_error if the API is not found or the signature does
  /// not match.
  template <typename FuncSignature>
  std::function<FuncSignature> getExportedApi(const std::string& name)
  {
    std::lock_guard<std::mutex> lock(_apiMutex);
    auto it = _apiExports.find(name);
    if (it == _apiExports.end())
    {
      throw std::runtime_error("API not found: " + name);
    }
    try
    {
      return std::any_cast<std::function<FuncSignature>>(it->second);
    }
    catch (const std::bad_any_cast&)
    {
      throw std::runtime_error("API signature mismatch for: " + name);
    }
  }

  /// \brief Calls a registered plugin API by name with arguments.
  /// Throws std::runtime_error if the API is not found or the signature does
  /// not match.
  template <typename Ret, typename... Args>
  Ret callExportedApi(const std::string& name, Args&&... args)
  {
    auto func = getExportedApi<Ret(Args...)>(name);
    return func(std::forward<Args>(args)...);
  }

  // --- Fluent API builder class declarations ---
  class RouteBuilder;
  class EventBuilder;

  /// \brief Begin fluent registration of a webhook endpoint.
  RouteBuilder on(const std::string& endpoint);

  /// \brief Begin fluent registration of an event handler.
  EventBuilder onEvent(const std::string& eventId);

  /// \brief Begin fluent registration of an event handler by name.
  EventBuilder onEventName(const std::string& eventName);

  /// \brief Begin fluent registration of an event handler matching a name
  EventBuilder onEventNameMatches(const std::string& eventNamePattern);

  /// \brief Loads a single module from the specified path with security
  /// validation.
  bool loadSingleModule(const std::string& modulePath)
  {
    try
    {
      // Validate path to prevent directory traversal attacks
      if (!validateModulePath(modulePath))
      {
        LOG_ERROR("Invalid or unsafe module path: " + modulePath);
        return false;
      }

      std::filesystem::path entry(modulePath);
      if (!std::filesystem::exists(entry) ||
          !std::filesystem::is_regular_file(entry))
      {
        LOG_ERROR("Module path does not exist or is not a file: " + modulePath);
        return false;
      }

      // Additional security check for file extension
      std::string extension = entry.extension().string();
      const std::vector<std::string> allowedExtensions = {".so", ".dll",
                                                          ".dylib"};
      if (std::find(allowedExtensions.begin(), allowedExtensions.end(),
                    extension) == allowedExtensions.end())
      {
        LOG_ERROR("Module has unsupported file extension: " + modulePath);
        return false;
      }

      return loadSingleModule(std::filesystem::directory_entry(entry));
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("Failed to load module: " + modulePath + " - " + e.what());
      return false;
    }
  }

  bool unloadSingleModule(const std::string& pluginName)
  {
    std::lock_guard<std::mutex> lock(_loadModulesMutex);
    auto it = _loadedModules.find(pluginName);
    if (it != _loadedModules.end())
    {
      auto& pluginPtr = it->second;
      if (pluginPtr)
      {
        try
        {
          pluginPtr->onUnload();
          for (auto& apiName : pluginPtr->_apiExports)
          {
            unexportApi(apiName);
          }
          _loadedModules.erase(it); // unique_ptr will delete
          unloadPlugin(pluginName);
          LOG_INFO("Plugin " + pluginName + " unloaded successfully.");
          return true;
        }
        catch (const std::exception& e)
        {
          LOG_ERROR("Failed to unload plugin: " + pluginName + " - " +
                    e.what());
        }
      }
    }
    else
    {
      LOG_ERROR("Plugin not found: " + pluginName);
    }
    return false;
  }

  bool reloadModule(const std::string& pluginName)
  {
    return unloadSingleModule(pluginName) && loadSingleModule(pluginName);
  }

  bool unloadAllModules()
  {
    std::lock_guard<std::mutex> lock(_loadModulesMutex);
    bool success = true;
    for (auto it = _loadedModules.begin(); it != _loadedModules.end();)
    {
      const std::string& name = it->first;
      auto& pluginPtr = it->second;
      if (pluginPtr)
      {
        try
        {
          pluginPtr->onUnload();
          for (auto& apiName : pluginPtr->_apiExports)
          {
            unexportApi(apiName);
          }
          unloadPlugin(name);
          LOG_INFO("Plugin " + name + " unloaded successfully.");
        }
        catch (const std::exception& e)
        {
          LOG_ERROR("Failed to unload plugin: " + name + " - " + e.what());
          success = false;
        }
      }
      it = _loadedModules.erase(it); // unique_ptr will delete
    }
    _loadedModules.clear();
    return success;
  }

private:
  /// \brief Validates module path to prevent directory traversal and other
  /// security issues.
  static bool validateModulePath(const std::string& path)
  {
    try
    {
      // Check for directory traversal attempts
      if (path.find("..") != std::string::npos ||
          path.find("/.") != std::string::npos ||
          path.find("\\.") != std::string::npos)
      {
        return false;
      }

      // Canonicalize the path
      std::filesystem::path canonicalPath =
          std::filesystem::canonical(
              std::filesystem::path(path).parent_path()) /
          std::filesystem::path(path).filename();

      // Ensure the canonical path doesn't contain suspicious elements
      std::string canonicalStr = canonicalPath.string();
      if (canonicalStr.find("..") != std::string::npos)
      {
        return false;
      }

      // Additional checks for common attack patterns
      if (path.empty() || path.size() > 4096) // Path too long
      {
        return false;
      }

      // Check for null bytes or other control characters
      for (char c : path)
      {
        if (c == '\0' ||
            (c >= 1 && c <= 31 && c != '\t' && c != '\n' && c != '\r'))
        {
          return false;
        }
      }

      return true;
    }
    catch (const std::exception&)
    {
      return false; // Any filesystem error means path is invalid
    }
  }

protected:
  /// \brief Retrieves the global instance pointer directly.
  static std::unique_ptr<IoraService>& getInstancePtr()
  {
    static std::unique_ptr<IoraService> instance;
    return instance;
  }

  /// \brief Retrieves the global instance of the service using thread-safe
  /// initialization.
  static std::unique_ptr<IoraService>& instancePtr()
  {
    static std::mutex instanceMutex;
    std::lock_guard<std::mutex> lock(instanceMutex);

    auto& instance = getInstancePtr();
    if (!instance)
    {
      instance = std::make_unique<IoraService>();
    }

    return instance;
  }

  /// \brief Explicitly destroy the singleton instance (for test shutdown order)
  static void destroyInstance()
  {
    static std::mutex instanceMutex;
    std::lock_guard<std::mutex> lock(instanceMutex);
    getInstancePtr().reset();
  }

  bool loadSingleModule(const std::filesystem::directory_entry& entry)
  {
    std::lock_guard<std::mutex> lock(_loadModulesMutex);
    try
    {
      std::string pluginName = entry.path().filename().string();
      LOG_INFO("Loading module: " + pluginName);
      loadPlugin(pluginName, entry.path().string());

      // Resolve and call the exported loadModule function
      using LoadModuleFunc = Plugin* (*) (iora::IoraService*);
      auto loadModule = resolve<LoadModuleFunc>(pluginName, "loadModule");
      std::unique_ptr<Plugin> pluginInstance(loadModule(this));
      if (pluginInstance)
      {
        pluginInstance->_name = pluginName;            // Set the plugin name
        pluginInstance->_path = entry.path().string(); // Set the plugin path
        pluginInstance->onLoad(this);
        _loadedModules.insert({pluginName, std::move(pluginInstance)});
        LOG_INFO("Module " + pluginName + " loaded successfully.");
      }
      else
      {
        LOG_ERROR("Module " + pluginName + " did not return a valid instance.");
        return false;
      }
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("Failed to load module: " + entry.path().string() + " - " +
                e.what());
      return false;
    }
    return true;
  }

  void loadModules()
  {
    if (_modulesPath.empty())
    {
      LOG_INFO("No modules specified, skipping plugin loading.");
      return;
    }
    LOG_INFO("Loading modules from: " + _modulesPath);
    std::filesystem::path modulesPath(_modulesPath);
    if (!std::filesystem::exists(modulesPath))
    {
      LOG_ERROR("Modules path does not exist: " + _modulesPath);
      return;
    }
    if (!std::filesystem::is_directory(modulesPath))
    {
      LOG_ERROR("Modules path is not a directory: " + _modulesPath);
      return;
    }

    if (_config.modules.modules.has_value() &&
        !_config.modules.modules->empty())
    {
      for (const auto& moduleName : *_config.modules.modules)
      {
        std::filesystem::path modulePath = modulesPath / moduleName;
        if (std::filesystem::exists(modulePath) &&
            std::filesystem::is_regular_file(modulePath))
        {
          loadSingleModule(modulePath.string());
        }
        else
        {
          LOG_ERROR("Module not found: " + modulePath.string());
        }
      }
      return;
    }
    else
    {
      const std::vector<std::string> supportedExtensions = {".so", ".dll"};
      for (const auto& entry : std::filesystem::directory_iterator(modulesPath))
      {
        if (entry.is_regular_file() &&
            std::find(supportedExtensions.begin(), supportedExtensions.end(),
                      entry.path().extension()) != supportedExtensions.end())
        {
          loadSingleModule(entry);
        }
      }
    }
    LOG_INFO("Module loading complete.");
  }

  /// \brief Unregisters a plugin API by name.
  /// Throws std::runtime_error if the API is not found.
  void unexportApi(const std::string& name)
  {
    std::lock_guard<std::mutex> lock(_apiMutex);
    auto it = _apiExports.find(name);
    if (it == _apiExports.end())
    {
      throw std::runtime_error("Plugin API not found: " + name);
    }
    _apiExports.erase(it);
  }

  /// \brief Parses command-line arguments and stores CLI overrides in _config.
  void parseCliArgs(int argc, char** argv)
  {
    for (int i = 1; i < argc; ++i)
    {
      std::string arg = argv[i];
      if ((arg == "-p" || arg == "--port") && i + 1 < argc)
      {
        try
        {
          _config.server.port = std::stoi(argv[++i]);
        }
        catch (...)
        {
        }
      }
      else if ((arg == "-c" || arg == "--config") && i + 1 < argc)
      {
        _configLoader = std::make_unique<core::ConfigLoader>(argv[++i]);
      }
      else if ((arg == "-s" || arg == "--state-file") && i + 1 < argc)
      {
        _config.state.file = argv[++i];
      }
      else if ((arg == "-l" || arg == "--log-level") && i + 1 < argc)
      {
        _config.log.level = argv[++i];
      }
      else if ((arg == "-f" || arg == "--log-file") && i + 1 < argc)
      {
        _config.log.file = argv[++i];
      }
      else if ((arg == "-m" || arg == "--modules") && i + 1 < argc)
      {
        _config.modules.directory = argv[++i];
      }
      else if (arg == "--log-async" && i + 1 < argc)
      {
        std::string val = argv[++i];
        std::transform(val.begin(), val.end(), val.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(std::tolower(c)); });
        if (val == "true" || val == "1" || val == "yes")
          _config.log.async = true;
        else if (val == "false" || val == "0" || val == "no")
          _config.log.async = false;
      }
      else if (arg == "--log-retention" && i + 1 < argc)
      {
        try
        {
          _config.log.retentionDays = std::stoi(argv[++i]);
        }
        catch (...)
        {
        }
      }
      else if (arg == "--log-time-format" && i + 1 < argc)
      {
        _config.log.timeFormat = argv[++i];
      }
      // TLS CLI
      else if (arg == "--tls-cert" && i + 1 < argc)
      {
        _config.server.tls.certFile = argv[++i];
      }
      else if (arg == "--tls-key" && i + 1 < argc)
      {
        _config.server.tls.keyFile = argv[++i];
      }
      else if (arg == "--tls-ca" && i + 1 < argc)
      {
        _config.server.tls.caFile = argv[++i];
      }
      else if (arg == "--tls-require-client-cert" && i + 1 < argc)
      {
        std::string val = argv[++i];
        std::transform(val.begin(), val.end(), val.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(std::tolower(c)); });
        if (val == "true" || val == "1" || val == "yes")
          _config.server.tls.requireClientCert = true;
        else if (val == "false" || val == "0" || val == "no")
          _config.server.tls.requireClientCert = false;
      }
      // Unrecognised arguments are ignored.
    }
  }

  /// \brief Loads TOML configuration and updates _config with file values.
  void parseTomlConfig()
  {
    try
    {
      if (!_configLoader)
      {
        _configLoader = std::make_unique<core::ConfigLoader>("config.toml");
      }
      _configLoader->reload();
      if (!_config.server.port.has_value())
      {
        if (auto portOpt = _configLoader->getInt("iora.server.port"))
        {
          _config.server.port = static_cast<int>(*portOpt);
        }
      }
      if (!_config.modules.directory.has_value())
      {
        if (auto modulesDirOpt =
                _configLoader->getString("iora.modules.directory"))
        {
          _config.modules.directory = *modulesDirOpt;
        }
      }
      if (!_config.modules.modules.has_value())
      {
        if (auto modulesOpt =
                _configLoader->getStringArray("iora.modules.modules"))
        {
          _config.modules.modules = *modulesOpt;
        }
      }
      if (!_config.state.file.has_value())
      {
        if (auto stateFileOpt = _configLoader->getString("iora.state.file"))
        {
          _config.state.file = *stateFileOpt;
        }
      }
      if (!_config.log.level.has_value())
      {
        if (auto logLevelOpt = _configLoader->getString("iora.log.level"))
        {
          _config.log.level = *logLevelOpt;
        }
      }
      if (!_config.log.file.has_value())
      {
        if (auto logFileOpt = _configLoader->getString("iora.log.file"))
        {
          _config.log.file = *logFileOpt;
        }
      }
      if (!_config.log.async.has_value())
      {
        if (auto logAsyncOpt = _configLoader->getBool("iora.log.async"))
        {
          _config.log.async = *logAsyncOpt;
        }
      }
      if (!_config.log.retentionDays.has_value())
      {
        if (auto logRetentionOpt =
                _configLoader->getInt("iora.log.retention_days"))
        {
          _config.log.retentionDays = static_cast<int>(*logRetentionOpt);
        }
      }
      if (!_config.log.timeFormat.has_value())
      {
        if (auto logTimeFormatOpt =
                _configLoader->getString("iora.log.time_format"))
        {
          _config.log.timeFormat = *logTimeFormatOpt;
        }
      }
      // TLS config from TOML
      if (!_config.server.tls.certFile.has_value())
      {
        if (auto tlsCertOpt =
                _configLoader->getString("iora.server.tls.cert_file"))
        {
          _config.server.tls.certFile = *tlsCertOpt;
        }
      }
      if (!_config.server.tls.keyFile.has_value())
      {
        if (auto tlsKeyOpt =
                _configLoader->getString("iora.server.tls.key_file"))
        {
          _config.server.tls.keyFile = *tlsKeyOpt;
        }
      }
      if (!_config.server.tls.caFile.has_value())
      {
        if (auto tlsCaOpt = _configLoader->getString("iora.server.tls.ca_file"))
        {
          _config.server.tls.caFile = *tlsCaOpt;
        }
      }
      if (!_config.server.tls.requireClientCert.has_value())
      {
        if (auto tlsReqOpt =
                _configLoader->getBool("iora.server.tls.require_client_cert"))
        {
          _config.server.tls.requireClientCert = *tlsReqOpt;
        }
      }
    }
    catch (...)
    {
      // Ignore errors and keep defaults.
    }
  }

  /// \brief Applies the merged configuration in _config to the service.
  void applyConfig()
  {
    if (_isRunning)
    {
      LOG_ERROR("applyConfig: Cannot apply config while service is running");
      throw std::runtime_error("Cannot apply config while service is running");
    }
    // Fill in defaults for any unset config values
    const int DEFAULT_PORT = 8080;
    const char* DEFAULT_STATE_FILE = "state.json";
    const char* DEFAULT_LOG_LEVEL = "info";
    const char* DEFAULT_LOG_FILE = "";
    const bool DEFAULT_LOG_ASYNC = false;
    const int DEFAULT_LOG_RETENTION = 7;
    const char* DEFAULT_LOG_TIME_FORMAT = "%Y-%m-%d %H:%M:%S";

    // Logger: must be initialized first
    auto toLevel = [](const std::string& s)
    {
      std::string v;
      v.reserve(s.size());
      for (char c : s)
      {
        v.push_back(
            static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
      }
      if (v == "trace")
        return core::Logger::Level::Trace;
      if (v == "debug")
        return core::Logger::Level::Debug;
      if (v == "warn" || v == "warning")
        return core::Logger::Level::Warning;
      if (v == "error")
        return core::Logger::Level::Error;
      if (v == "fatal")
        return core::Logger::Level::Fatal;
      return core::Logger::Level::Info;
    };
    std::string logLevel = _config.log.level.value_or(DEFAULT_LOG_LEVEL);
    std::string logFile = _config.log.file.value_or(DEFAULT_LOG_FILE);
    bool logAsync = _config.log.async.value_or(DEFAULT_LOG_ASYNC);
    int logRetention =
        _config.log.retentionDays.value_or(DEFAULT_LOG_RETENTION);
    std::string logTimeFormat =
        _config.log.timeFormat.value_or(DEFAULT_LOG_TIME_FORMAT);
    core::Logger::init(toLevel(logLevel), logFile, logAsync, logRetention,
                      logTimeFormat);
    LOG_INFO("applyConfig: Logger initialized");

    // Log config values for diagnostics (now logger is ready)
    LOG_INFO(
        "applyConfig: state.file = " << _config.state.file.value_or("<unset>"));
    LOG_INFO(
        "applyConfig: log.level = " << _config.log.level.value_or("<unset>"));
    LOG_INFO(
        "applyConfig: log.file = " << _config.log.file.value_or("<unset>"));
    LOG_INFO("applyConfig: log.async = "
             << (_config.log.async.has_value()
                     ? (_config.log.async.value() ? "true" : "false")
                     : "<unset>"));
    LOG_INFO("applyConfig: log.retentionDays = "
             << (_config.log.retentionDays.has_value()
                     ? std::to_string(_config.log.retentionDays.value())
                     : "<unset>"));
    LOG_INFO("applyConfig: log.timeFormat = "
             << _config.log.timeFormat.value_or("<unset>"));
    LOG_INFO("applyConfig: server.port = "
             << (_config.server.port.has_value()
                     ? std::to_string(_config.server.port.value())
                     : "<unset>"));
    LOG_INFO("applyConfig: server.tls.certFile = "
             << _config.server.tls.certFile.value_or("<unset>"));
    LOG_INFO("applyConfig: server.tls.keyFile = "
             << _config.server.tls.keyFile.value_or("<unset>"));
    LOG_INFO("applyConfig: server.tls.caFile = "
             << _config.server.tls.caFile.value_or("<unset>"));
    LOG_INFO("applyConfig: server.tls.requireClientCert = "
             << (_config.server.tls.requireClientCert.has_value()
                     ? (_config.server.tls.requireClientCert.value() ? "true"
                                                                     : "false")
                     : "<unset>"));
    LOG_INFO("applyConfig: modules.directory = "
             << _config.modules.directory.value_or("<unset>"));

    // State file
    std::string stateFile = _config.state.file.value_or(DEFAULT_STATE_FILE);
    LOG_INFO("applyConfig: Creating JsonFileStore at: " << stateFile);
    _jsonFileStore = std::make_unique<storage::JsonFileStore>(stateFile);
    assert(_jsonFileStore && "_jsonFileStore must be initialized after config");
    LOG_INFO("applyConfig: JsonFileStore created at: " << stateFile);

    // Webhook Server
    _webhookServer = std::make_unique<network::WebhookServer>();
    auto port = _config.server.port.value_or(DEFAULT_PORT);
    LOG_INFO("applyConfig: Setting webhook server port to: " << port);
    _webhookServer->setPort(port);

    // TLS
    bool hasTls = _config.server.tls.certFile.has_value() ||
                  _config.server.tls.keyFile.has_value() ||
                  _config.server.tls.caFile.has_value() ||
                  _config.server.tls.requireClientCert.value_or(false);
    if (hasTls)
    {
      LOG_INFO("applyConfig: TLS is enabled");
      network::WebhookServer::TlsConfig tlsCfg;
      tlsCfg.certFile = _config.server.tls.certFile.value_or("");
      tlsCfg.keyFile = _config.server.tls.keyFile.value_or("");
      tlsCfg.caFile = _config.server.tls.caFile.value_or("");
      tlsCfg.requireClientCert =
          _config.server.tls.requireClientCert.value_or(false);
      LOG_INFO("applyConfig: Enabling TLS with certFile=" + tlsCfg.certFile +
               ", keyFile=" + tlsCfg.keyFile + ", caFile=" + tlsCfg.caFile +
               ", requireClientCert=" +
               (tlsCfg.requireClientCert ? "true" : "false"));
      _webhookServer->enableTls(tlsCfg);
    }
    else
    {
      LOG_INFO("applyConfig: TLS is not enabled");
    }

    // Modules path
    if (_config.modules.directory.has_value())
    {
      _modulesPath = _config.modules.directory.value();
    }

    // State store
    _stateStore = std::make_unique<storage::ConcreteStateStore>();

    // Expiring cache
    _cache = std::make_unique<util::ExpiringCache<std::string, std::string>>(
        std::chrono::minutes(1)); // Default flush interval of 1 minute

    LOG_INFO("applyConfig: Loading modules");
    loadModules();
    LOG_INFO("applyConfig: Configuration applied");

    // Start the webhook server
    try
    {
      _webhookServer->start();
    }
    catch (const std::exception& ex)
    {
      LOG_ERROR("applyConfig: Failed to start webhook server: " +
                std::string(ex.what()));
      throw;
    }

    _isRunning = true;
  }

  /// \brief Parses CLI args, loads TOML config, and applies merged config.
  void parseConfig(int argc, char** argv)
  {
    parseCliArgs(argc, argv);
    parseTomlConfig();
    applyConfig();
  }

private:
  // For main thread blocking/termination
  std::mutex _terminationMutex;
  std::condition_variable _terminationCv;
  bool _terminated = false;
  // Track loaded plugin instances for proper onUnload notification
  std::unordered_map<std::string, std::unique_ptr<Plugin>> _loadedModules;
  std::unique_ptr<network::WebhookServer> _webhookServer;
  std::unique_ptr<storage::ConcreteStateStore> _stateStore;
  std::unique_ptr<util::ExpiringCache<std::string, std::string>> _cache;
  std::unique_ptr<core::ConfigLoader> _configLoader;
  std::unique_ptr<storage::JsonFileStore> _jsonFileStore;
  std::string _modulesPath;
  /// \brief EventQueue for managing and dispatching events
  util::EventQueue _eventQueue{4}; // Default to 4 worker threads
  std::unordered_map<std::string, std::any> _apiExports;
  std::mutex _loadModulesMutex; // Mutex for thread-safe module loading
  std::mutex _apiMutex;
  std::atomic<bool> _isRunning{false};

  /// \brief Holds the merged configuration (CLI, TOML, defaults).
  Config _config;
};

class IoraService::RouteBuilder
{
public:
  RouteBuilder(network::WebhookServer& server, const std::string& endpoint)
    : _server(server), _endpoint(endpoint)
  {
  }

  void handleJson(const network::WebhookServer::JsonHandler& handler)
  {
    _server.onJsonPost(_endpoint, handler);
  }

private:
  network::WebhookServer& _server;
  std::string _endpoint;
};

class IoraService::EventBuilder
{
public:
  enum class EventType
  {
    ID,
    NAME,
    NAME_MATCHES
  };

  EventBuilder(util::EventQueue& queue, const std::string& eventId,
               EventType type)
    : _queue(queue), _eventId(eventId), _eventType(type)
  {
  }

  void handle(const util::EventQueue::Handler& handler)
  {
    if (_eventType == EventType::NAME)
    {
      _queue.onEventName(_eventId, handler);
    }
    else if (_eventType == EventType::NAME_MATCHES)
    {
      _queue.onEventNameMatches(_eventId, handler);
    }
    else if (_eventType == EventType::ID)
    {
      _queue.onEventId(_eventId, handler);
    }
    else
    {
      throw std::invalid_argument("Invalid event type specified");
    }
  }

private:
  util::EventQueue& _queue;
  std::string _eventId;
  EventType _eventType = EventType::ID; // Default to ID type
};

inline IoraService::RouteBuilder IoraService::on(const std::string& endpoint)
{
  // Use the accessor to ensure runtime check
  return RouteBuilder(*_webhookServer, endpoint);
}

inline IoraService::EventBuilder
IoraService::onEvent(const std::string& eventId)
{
  return EventBuilder(_eventQueue, eventId, EventBuilder::EventType::ID);
}

inline IoraService::EventBuilder
IoraService::onEventName(const std::string& eventName)
{
  return EventBuilder(_eventQueue, eventName, EventBuilder::EventType::NAME);
}

inline IoraService::EventBuilder
IoraService::onEventNameMatches(const std::string& eventNamePattern)
{
  return EventBuilder(_eventQueue, eventNamePattern,
                      EventBuilder::EventType::NAME_MATCHES);
}

using IoraPlugin = IoraService::Plugin;
#define IORA_DECLARE_PLUGIN(PluginType)                                        \
  extern "C" iora::IoraPlugin* loadModule(iora::IoraService* service)          \
  {                                                                            \
    try                                                                        \
    {                                                                          \
      PluginType* instance = new PluginType(service);                          \
      return instance;                                                         \
    }                                                                          \
    catch (const std::exception& e)                                            \
    {                                                                          \
      iora::core::Logger::error("Plugin initialization failed: " +              \
                               std::string(e.what()));                         \
      return nullptr;                                                          \
    }                                                                          \
  }

} // namespace iora