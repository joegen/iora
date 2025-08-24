// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <any>
#include <cassert>
#include "core/config_loader.hpp"
#include "core/event_queue.hpp"
#include "core/logger.hpp"
#include "core/plugin_loader.hpp"
#include "core/thread_pool.hpp"
#include "network/http_client.hpp"
#include "network/webhook_server.hpp"
#include "parsers/json.hpp"
#include "parsers/xml.hpp"
#include "storage/concrete_state_store.hpp"
#include "storage/json_file_store.hpp"
#include "system/shell_runner.hpp"
#include "util/expiring_cache.hpp"
#include "util/filesystem.hpp"

#define IORA_DEFAULT_CONFIG_FILE_PATH "/etc/iora.conf.d/iora.cfg"

namespace iora
{

  /// \brief Singleton entry point for the Iora library, managing all core
  /// components and providing factory methods for utilities and plugins.
  class IoraService : private core::PluginManager
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
        core::Logger::error("IoraService destructor error: " + std::string(e.what()));
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
        std::optional<bool> autoLoad;
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
      struct ThreadPool
      {
        std::optional<std::size_t> minThreads;
        std::optional<std::size_t> maxThreads;
        std::optional<std::size_t> queueSize;
        std::optional<std::chrono::seconds> idleTimeoutSeconds;
      } threadPool;

      // Configuration file path (used for CLI parsing)
      std::optional<std::string> configFile;
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

        svc._config = Config();  // Reset configuration
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
          core::Logger::error("IoraService shutdown error: " + std::string(e.what()));
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

      IoraService* service() const
      {
        return _service;
      }

     private:
      IoraService* _service = nullptr;
      std::vector<std::string> _apiExports;  // APIs this plugin exports
      std::string _name;                     // Plugin name for identification
      std::string _path;                     // Path to the plugin library
      friend class IoraService;              // Allow IoraService to access private members
    };

    /// \brief RAII wrapper to automatically shutdown the IoraService
    class AutoServiceShutdown
    {
     public:
      explicit AutoServiceShutdown(iora::IoraService& service) : _svc(service) {}
      ~AutoServiceShutdown()
      {
        IoraService::shutdown();
      }

     private:
      iora::IoraService& _svc;
    };

    /// \brief Initialises the singleton with a configuration object.
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
    const std::unique_ptr<util::ExpiringCache<std::string, std::string>>& cache() const
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

    /// \brief Get the thread pool instance.
    const std::unique_ptr<core::ThreadPool>& threadPool() const
    {
      return _threadPool;
    }

    /// \brief Factory for creating a JSON file store backed by the given file.
    std::unique_ptr<storage::JsonFileStore> makeJsonFileStore(const std::string& filename) const
    {
      core::Logger::info("IoraService: Creating JSON file store for file: " + filename);
      return std::make_unique<storage::JsonFileStore>(filename);
    }

    /// \brief Factory for creating a new stateless HTTP client.
    network::HttpClient makeHttpClient() const
    {
      core::Logger::debug("IoraService: Creating new HTTP client instance");
      return network::HttpClient{};
    }

    /// \brief Push an event to the EventQueue
    void pushEvent(const parsers::Json& event)
    {
      std::string eventId = event.contains("eventId") ? event["eventId"].get<std::string>() : "<unknown>";
      std::string eventName = event.contains("eventName") ? event["eventName"].get<std::string>() : "<unknown>";
      core::Logger::debug("IoraService: Pushing event (id=" + eventId + ", name=" + eventName + ") to event queue");
      _eventQueue.push(event);
    }

    /// \brief Register a handler for an event by its ID
    void registerEventHandlerById(const std::string& eventId, core::EventQueue::Handler handler)
    {
      core::Logger::info("IoraService: Registering event handler for event ID: " + eventId);
      _eventQueue.onEventId(eventId, std::move(handler));
    }

    /// \brief Register a handler for an event by its name
    void registerEventHandlerByName(const std::string& eventName, core::EventQueue::Handler handler)
    {
      core::Logger::info("IoraService: Registering event handler for event name: " + eventName);
      _eventQueue.onEventName(eventName, std::move(handler));
    }

    /// \brief Provides access to the EventQueue for managing events.
    core::EventQueue& eventQueue()
    {
      return _eventQueue;
    }

    /// \brief Registers a plugin API function that can be called by plugins.
    template <typename Func>
    void exportApi(Plugin& plugin, const std::string& name, Func&& func)
    {
      if (name.empty())
      {
        core::Logger::error("IoraService::exportApi() - Plugin API name cannot be empty");
        throw std::invalid_argument("Plugin API name cannot be empty");
      }
      if (_apiExports.find(name) != _apiExports.end())
      {
        core::Logger::error("IoraService::exportApi() - Plugin API already registered: " + name);
        throw std::runtime_error("Plugin API already registered: " + name);
      }
      core::Logger::info("IoraService::exportApi() - Registering plugin API: " + name + " for plugin: " + plugin._name);
      std::lock_guard<std::mutex> lock(_apiMutex);
      using func_type = std::decay_t<Func>;
      using signature = decltype(&func_type::operator());
      _apiExports[name] = makeStdFunction(std::forward<Func>(func), signature{});
      plugin._apiExports.push_back(name);
    }

    // Helper to deduce lambda signature and wrap in std::function
    template <typename Func, typename Ret, typename... Args>
    static std::function<Ret(Args...)> makeStdFunction(Func&& f, Ret (Func::*)(Args...) const)
    {
      return std::function<Ret(Args...)>(std::forward<Func>(f));
    }
    template <typename Func, typename Ret, typename... Args>
    static std::function<Ret(Args...)> makeStdFunction(Func&& f, Ret (Func::*)(Args...))
    {
      return std::function<Ret(Args...)>(std::forward<Func>(f));
    }

    // Forward declaration for safe API wrapper
    template <typename FuncSignature>
    class SafeApiFunction;

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

    /// \brief Retrieves a safe wrapper for a plugin API that handles module
    /// unloading gracefully. Uses event-based caching for optimal performance.
    template <typename FuncSignature>
    SafeApiFunction<FuncSignature> getExportedApiSafe(const std::string& name)
    {
      return SafeApiFunction<FuncSignature>(name, this);
    }

    /// \brief Retrieves the names of all exported APIs.
    std::vector<std::string> getExportedApiNames() const
    {
      std::lock_guard<std::mutex> lock(_apiMutex);
      std::vector<std::string> names;
      for (const auto& kv : _apiExports)
      {
        names.push_back(kv.first);
      }
      return names;
    }

    /// \brief Calls a registered plugin API by name with arguments.
    /// Throws std::runtime_error if the API is not found or the signature does
    /// not match.
    template <typename Ret, typename... Args>
    Ret callExportedApi(const std::string& name, Args&&... args)
    {
      core::Logger::debug("IoraService::callExportedApi() - Calling plugin API: " + name);
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
        if (!std::filesystem::exists(entry) || !std::filesystem::is_regular_file(entry))
        {
          LOG_ERROR("Module path does not exist or is not a file: " + modulePath);
          return false;
        }

        // Additional security check for file extension
        std::string extension = entry.extension().string();
        const std::vector<std::string> allowedExtensions = {".so", ".dll", ".dylib"};
        if (std::find(allowedExtensions.begin(), allowedExtensions.end(), extension) == allowedExtensions.end())
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
            _loadedModules.erase(it);  // unique_ptr will delete
            PluginManager::unloadPlugin(pluginName);
            LOG_INFO("Plugin " + pluginName + " unloaded successfully.");

            // Emit module unloaded event
            auto event = parsers::Json::object();
            event["eventId"] = "module_unloaded_" + pluginName;
            event["eventName"] = "module.unload." + pluginName;
            event["moduleName"] = pluginName;
            pushEvent(event);

            return true;
          }
          catch (const std::exception& e)
          {
            LOG_ERROR("Failed to unload plugin: " + pluginName + " - " + e.what());
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

    /// \brief Check if a module is currently loaded
    bool isModuleLoaded(const std::string& moduleName) const
    {
      std::lock_guard<std::mutex> lock(_loadModulesMutex);
      return _loadedModules.find(moduleName) != _loadedModules.end();
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
            PluginManager::unloadPlugin(name);
            LOG_INFO("Plugin " + name + " unloaded successfully.");
          }
          catch (const std::exception& e)
          {
            LOG_ERROR("Failed to unload plugin: " + name + " - " + e.what());
            success = false;
          }
        }
        it = _loadedModules.erase(it);  // unique_ptr will delete
      }
      _loadedModules.clear();
      return success;
    }

    /// \brief Sets the configuration loader for the service.
    void setConfigLoader(std::unique_ptr<core::ConfigLoader>&& loader)
    {
      _configLoader = std::move(loader);
    }

   private:
    /// \brief Validates module path to prevent directory traversal and other
    /// security issues.
    static bool validateModulePath(const std::string& path)
    {
      try
      {
        // Check for directory traversal attempts
        if (path.find("..") != std::string::npos || path.find("/.") != std::string::npos ||
            path.find("\\.") != std::string::npos)
        {
          return false;
        }

        // Canonicalize the path
        std::filesystem::path canonicalPath = std::filesystem::canonical(std::filesystem::path(path).parent_path()) /
                                              std::filesystem::path(path).filename();

        // Ensure the canonical path doesn't contain suspicious elements
        std::string canonicalStr = canonicalPath.string();
        if (canonicalStr.find("..") != std::string::npos)
        {
          return false;
        }

        // Additional checks for common attack patterns
        if (path.empty() || path.size() > 4096)  // Path too long
        {
          return false;
        }

        // Check for null bytes or other control characters
        for (char c : path)
        {
          if (c == '\0' || (c >= 1 && c <= 31 && c != '\t' && c != '\n' && c != '\r'))
          {
            return false;
          }
        }

        return true;
      }
      catch (const std::exception&)
      {
        return false;  // Any filesystem error means path is invalid
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
        using LoadModuleFunc = Plugin* (*)(iora::IoraService*);
        auto loadModule = resolve<LoadModuleFunc>(pluginName, "loadModule");
        std::unique_ptr<Plugin> pluginInstance(loadModule(this));
        if (pluginInstance)
        {
          pluginInstance->_name = pluginName;             // Set the plugin name
          pluginInstance->_path = entry.path().string();  // Set the plugin path
          try
          {
            pluginInstance->onLoad(this);
          }
          catch (const std::exception& e)
          {
            LOG_ERROR("Exception while calling onLoad for module " + pluginName + ": " + e.what());
          }

          _loadedModules.insert({pluginName, std::move(pluginInstance)});
          LOG_INFO("Module " + pluginName + " loaded successfully.");

          // Emit module loaded event
          auto event = parsers::Json::object();
          event["eventId"] = "module_loaded_" + pluginName;
          event["eventName"] = "module.load." + pluginName;
          event["moduleName"] = pluginName;
          event["modulePath"] = entry.path().string();
          pushEvent(event);
        }
        else
        {
          LOG_ERROR("Module " + pluginName + " did not return a valid instance.");
          return false;
        }
      }
      catch (const std::exception& e)
      {
        LOG_ERROR("Failed to load module: " + entry.path().string() + " - " + e.what());
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

      if (_config.modules.modules.has_value() && !_config.modules.modules->empty())
      {
        for (const auto& moduleName : *_config.modules.modules)
        {
          std::filesystem::path modulePath = modulesPath / moduleName;
          if (std::filesystem::exists(modulePath) && std::filesystem::is_regular_file(modulePath))
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
          if (entry.is_regular_file() && std::find(supportedExtensions.begin(), supportedExtensions.end(),
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
          v.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        if (v == "trace")
        {
          return core::Logger::Level::Trace;
        }
        if (v == "debug")
        {
          return core::Logger::Level::Debug;
        }
        if (v == "warn" || v == "warning")
        {
          return core::Logger::Level::Warning;
        }
        if (v == "error")
        {
          return core::Logger::Level::Error;
        }
        if (v == "fatal")
        {
          return core::Logger::Level::Fatal;
        }
        return core::Logger::Level::Info;
      };
      std::string logLevel = _config.log.level.value_or(DEFAULT_LOG_LEVEL);
      std::string logFile = _config.log.file.value_or(DEFAULT_LOG_FILE);
      bool logAsync = _config.log.async.value_or(DEFAULT_LOG_ASYNC);
      int logRetention = _config.log.retentionDays.value_or(DEFAULT_LOG_RETENTION);
      std::string logTimeFormat = _config.log.timeFormat.value_or(DEFAULT_LOG_TIME_FORMAT);
      try
      {
        core::Logger::init(toLevel(logLevel), logFile, logAsync, logRetention, logTimeFormat);
        LOG_INFO("applyConfig: Logger initialized");
      }
      catch (const std::exception& e)
      {
        LOG_WARN("applyConfig: Logger already initialized, skipping: " << e.what());
      }

      // Log config values for diagnostics (now logger is ready)
      LOG_INFO("applyConfig: state.file = " << _config.state.file.value_or("<unset>"));
      LOG_INFO("applyConfig: log.level = " << _config.log.level.value_or("<unset>"));
      LOG_INFO("applyConfig: log.file = " << _config.log.file.value_or("<unset>"));
      LOG_INFO("applyConfig: log.async = "
               << (_config.log.async.has_value() ? (_config.log.async.value() ? "true" : "false") : "<unset>"));
      LOG_INFO("applyConfig: log.retentionDays = " << (_config.log.retentionDays.has_value()
                                                           ? std::to_string(_config.log.retentionDays.value())
                                                           : "<unset>"));
      LOG_INFO("applyConfig: log.timeFormat = " << _config.log.timeFormat.value_or("<unset>"));
      LOG_INFO("applyConfig: server.port = "
               << (_config.server.port.has_value() ? std::to_string(_config.server.port.value()) : "<unset>"));
      LOG_INFO("applyConfig: server.tls.certFile = " << _config.server.tls.certFile.value_or("<unset>"));
      LOG_INFO("applyConfig: server.tls.keyFile = " << _config.server.tls.keyFile.value_or("<unset>"));
      LOG_INFO("applyConfig: server.tls.caFile = " << _config.server.tls.caFile.value_or("<unset>"));
      LOG_INFO("applyConfig: server.tls.requireClientCert = "
               << (_config.server.tls.requireClientCert.has_value()
                       ? (_config.server.tls.requireClientCert.value() ? "true" : "false")
                       : "<unset>"));
      LOG_INFO("applyConfig: modules.directory = " << _config.modules.directory.value_or("<unset>"));

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
      bool hasTls = _config.server.tls.certFile.has_value() || _config.server.tls.keyFile.has_value() ||
                    _config.server.tls.caFile.has_value() || _config.server.tls.requireClientCert.value_or(false);
      if (hasTls)
      {
        LOG_INFO("applyConfig: TLS is enabled");
        network::WebhookServer::TlsConfig tlsCfg;
        tlsCfg.certFile = _config.server.tls.certFile.value_or("");
        tlsCfg.keyFile = _config.server.tls.keyFile.value_or("");
        tlsCfg.caFile = _config.server.tls.caFile.value_or("");
        tlsCfg.requireClientCert = _config.server.tls.requireClientCert.value_or(false);
        LOG_INFO("applyConfig: Enabling TLS with certFile=" + tlsCfg.certFile + ", keyFile=" + tlsCfg.keyFile +
                 ", caFile=" + tlsCfg.caFile + ", requireClientCert=" + (tlsCfg.requireClientCert ? "true" : "false"));
        _webhookServer->enableTls(tlsCfg);
      }
      else
      {
        LOG_INFO("applyConfig: TLS is not enabled");
      }

      // Start the webhook server
      LOG_INFO("applyConfig: Starting webhook server on port: " << port);
      try
      {
        _webhookServer->start();
        LOG_INFO("applyConfig: Webhook server started successfully");
      }
      catch (const std::exception& e)
      {
        LOG_ERROR("applyConfig: Failed to start webhook server: " << e.what());
        throw;
      }

      // Thread pool
      std::size_t minThreads = _config.threadPool.minThreads.value_or(1);
      std::size_t maxThreads = _config.threadPool.maxThreads.value_or(
          std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() : 4);
      std::size_t queueSize = _config.threadPool.queueSize.value_or(maxThreads * 2);
      std::chrono::seconds idleTimeout = _config.threadPool.idleTimeoutSeconds.value_or(std::chrono::seconds(60));
      _threadPool = std::make_unique<core::ThreadPool>(minThreads, maxThreads, idleTimeout, queueSize);

      // Config Loader
      if (!_configLoader)
      {
        std::string defaultConfigFile;
#ifdef IORA_DEFAULT_CONFIG_FILE_PATH
        defaultConfigFile = IORA_DEFAULT_CONFIG_FILE_PATH;
#endif
        std::string configFile = _config.configFile.value_or(defaultConfigFile);
        _configLoader = std::make_unique<core::ConfigLoader>(configFile);
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
          std::chrono::minutes(1));  // Default flush interval of 1 minute

      if (_config.modules.autoLoad.value_or(true))
      {
        LOG_INFO("applyConfig: Auto-loading modules is enabled");
        loadModules();
      }
      else
      {
        LOG_INFO("applyConfig: Auto-loading modules is disabled");
      }

      LOG_INFO("applyConfig: Configuration applied");

      // Start the webhook server

      _isRunning = true;
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
    std::unique_ptr<core::ThreadPool> _threadPool;
    std::string _modulesPath;
    /// \brief EventQueue for managing and dispatching events
    core::EventQueue _eventQueue{4};  // Default to 4 worker threads
    std::unordered_map<std::string, std::any> _apiExports;
    mutable std::mutex _loadModulesMutex;  // Mutex for thread-safe module loading
    mutable std::mutex _apiMutex;
    std::atomic<bool> _isRunning{false};

    /// \brief Holds the merged configuration (CLI, TOML, defaults).
    Config _config;
  };

  class IoraService::RouteBuilder
  {
   public:
    RouteBuilder(network::WebhookServer& server, const std::string& endpoint) : _server(server), _endpoint(endpoint) {}

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

    EventBuilder(core::EventQueue& queue, const std::string& eventId, EventType type)
        : _queue(queue), _eventId(eventId), _eventType(type)
    {
    }

    void handle(const core::EventQueue::Handler& handler)
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
    core::EventQueue& _queue;
    std::string _eventId;
    EventType _eventType = EventType::ID;  // Default to ID type
  };

  inline IoraService::RouteBuilder IoraService::on(const std::string& endpoint)
  {
    // Use the accessor to ensure runtime check
    return RouteBuilder(*_webhookServer, endpoint);
  }

  inline IoraService::EventBuilder IoraService::onEvent(const std::string& eventId)
  {
    return EventBuilder(_eventQueue, eventId, EventBuilder::EventType::ID);
  }

  inline IoraService::EventBuilder IoraService::onEventName(const std::string& eventName)
  {
    return EventBuilder(_eventQueue, eventName, EventBuilder::EventType::NAME);
  }

  inline IoraService::EventBuilder IoraService::onEventNameMatches(const std::string& eventNamePattern)
  {
    return EventBuilder(_eventQueue, eventNamePattern, EventBuilder::EventType::NAME_MATCHES);
  }

  /// \brief Thread-safe wrapper for exported API functions that handles module unloading gracefully.
  ///
  /// Features:
  /// - **Thread Safety**: Multiple threads can safely call the API concurrently
  /// - **Event-Based Caching**: Optimal performance - only validates when modules are unloaded/reloaded
  /// - **Crash Prevention**: Never calls invalid function pointers, throws clear exceptions instead
  /// - **Auto-Recovery**: Automatically works again when modules are reloaded
  ///
  /// Thread Safety Implementation:
  /// - Uses atomic<bool> for the validity flag
  /// - Mutex protects the cached function pointer updates
  /// - Double-checked locking pattern for performance
  /// - Event handlers use atomic operations
  template <typename R, typename... Args>
  class IoraService::SafeApiFunction<R(Args...)>
  {
   private:
    mutable std::function<R(Args...)> cachedFunc;
    mutable std::atomic<bool> valid{false};
    mutable std::mutex cacheMutex;  // Protects cachedFunc updates
    std::string apiName;
    std::string moduleName;
    IoraService* service;

    /// \brief Find module name from API name by checking all loaded modules
    std::string findModuleNameForApi(const std::string& apiName) const
    {
      std::lock_guard<std::mutex> lock(service->_loadModulesMutex);

      // Extract the prefix from API name (e.g., "testplugin.add" -> "testplugin")
      size_t dotPos = apiName.find('.');
      std::string apiPrefix = (dotPos != std::string::npos) ? apiName.substr(0, dotPos) : apiName;

      // Look for a loaded module whose name starts with the API prefix
      for (const auto& [moduleName, pluginPtr] : service->_loadedModules)
      {
        if (pluginPtr && moduleName.find(apiPrefix) == 0)
        {
          // Check if this module actually exports this API
          for (const auto& exportedApi : pluginPtr->_apiExports)
          {
            if (exportedApi == apiName)
            {
              return moduleName;  // Found the right module
            }
          }
        }
      }

      // Fallback: assume module name is prefix + ".so"
      return apiPrefix + ".so";
    }

   public:
    /// \brief Constructor that sets up event listening for module lifecycle
    SafeApiFunction(const std::string& name, IoraService* svc) : apiName(name), service(svc)
    {
      // Find the actual module name for this API
      moduleName = findModuleNameForApi(name);

      // Escape the module name for regex (dots need to be escaped)
      std::string escapedModuleName = moduleName;
      size_t pos = 0;
      while ((pos = escapedModuleName.find('.', pos)) != std::string::npos)
      {
        escapedModuleName.replace(pos, 1, "\\.");
        pos += 2;  // Move past the inserted escape sequence
      }

      // Listen for module unload/reload events for this specific module
      service->onEventNameMatches("^module\\.(unload|reload)\\." + escapedModuleName + "$")
          .handle(
              [this](const parsers::Json& event)
              {
                // Thread-safe invalidation of cache
                valid.store(false);
              });
    }

    /// \brief Function call operator - validates module and calls API (thread-safe)
    R operator()(Args... args) const
    {
      // Fast path: if valid and module is loaded, call directly
      if (valid.load() && service->isModuleLoaded(moduleName))
      {
        std::lock_guard<std::mutex> lock(cacheMutex);
        // Double-check after acquiring lock
        if (valid.load() && cachedFunc)
        {
          return cachedFunc(args...);
        }
      }

      // Slow path: need to refresh cache
      std::lock_guard<std::mutex> lock(cacheMutex);

      // Double-check pattern: another thread might have refreshed while we waited
      if (valid.load() && service->isModuleLoaded(moduleName) && cachedFunc)
      {
        return cachedFunc(args...);
      }

      // Module was unloaded/reloaded, or this is the first call
      if (!service->isModuleLoaded(moduleName))
      {
        valid.store(false);
        throw std::runtime_error("API '" + apiName + "' unavailable: module '" + moduleName + "' not loaded");
      }

      // Refresh the cached function
      try
      {
        cachedFunc = service->getExportedApi<R(Args...)>(apiName);
        valid.store(true);
        return cachedFunc(args...);
      }
      catch (const std::exception& e)
      {
        valid.store(false);
        throw std::runtime_error("Failed to refresh API '" + apiName + "': " + e.what());
      }
    }

    /// \brief Check if the API is currently available
    bool isAvailable() const
    {
      return service->isModuleLoaded(moduleName);
    }

    /// \brief Get the module name for this API
    const std::string& getModuleName() const
    {
      return moduleName;
    }

    /// \brief Get the API name
    const std::string& getApiName() const
    {
      return apiName;
    }
  };

  using IoraPlugin = IoraService::Plugin;
#define IORA_DECLARE_PLUGIN(PluginType)                                                                                \
  extern "C" iora::IoraPlugin* loadModule(iora::IoraService* service)                                                  \
  {                                                                                                                    \
    try                                                                                                                \
    {                                                                                                                  \
      PluginType* instance = new PluginType(service);                                                                  \
      return instance;                                                                                                 \
    }                                                                                                                  \
    catch (const std::exception& e)                                                                                    \
    {                                                                                                                  \
      iora::core::Logger::error("Plugin initialization failed: " + std::string(e.what()));                             \
      return nullptr;                                                                                                  \
    }                                                                                                                  \
  }

}  // namespace iora