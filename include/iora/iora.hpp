// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

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
#include <any>
#include <cassert>
#include <iostream>
#include <typeindex>

#define IORA_DEFAULT_CONFIG_FILE_PATH "/etc/iora.conf.d/iora.cfg"

namespace iora
{

/// \brief Singleton entry point for the Iora library, managing all core
/// components and providing factory methods for utilities and plugins.
class IoraService : private core::PluginManager
{
public:
  /// \brief Deleted copy constructor and assignment operator.
  IoraService(const IoraService &) = delete;
  IoraService &operator=(const IoraService &) = delete;

  /// \brief Constructor initialises members and loads configuration.
  IoraService() {}

  /// \brief Destructor stops the server with proper cleanup.
  /// Note: Logging in destructor may be unreliable if Logger is already destroyed
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
    catch (const std::exception &e)
    {
      // Try to log but don't throw from destructor
      // Note: Logger may already be destroyed, so this could fail silently
      try
      {
        core::Logger::error("IoraService destructor error: " + std::string(e.what()));
      }
      catch (...)
      {
        // Logger is likely destroyed - nothing we can do except write to stderr
        std::cerr << "IoraService destructor error (logger unavailable): " << e.what() << std::endl;
      }
    }
    catch (...)
    {
      try
      {
        core::Logger::error("IoraService destructor unknown error");
      }
      catch (...)
      {
        std::cerr << "IoraService destructor unknown error (logger unavailable)" << std::endl;
      }
    }
  }

  /// \brief Get a shared_ptr to the singleton instance for safe lifetime management
  static std::shared_ptr<IoraService> instance() { return instancePtr(); }

  /// \brief Get reference to singleton instance (for backward compatibility)
  /// WARNING: This can become invalid if destroyInstance() is called from another thread
  static IoraService &instanceRef()
  {
    auto ptr = instancePtr();
    // Note: instancePtr() always creates instance if it doesn't exist, so ptr is never null
    return *ptr;
  }

  /// \brief Holds all configuration options for IoraService, reflecting the
  /// nested TOML structure.
  struct Config
  {
    struct ServerConfig
    {
      std::optional<std::string> bindAddress;
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
      auto instancePtr = getInstancePtr();
      if (!instancePtr)
      {
        // Already shutdown or never initialized
        return;
      }

      IoraService &svc = *instancePtr;

      // Prevent double shutdown
      if (!svc._isRunning)
      {
        return;
      }

      // Mark as shutting down immediately to prevent reentrancy
      svc._isRunning = false;

      svc.unloadAllModules();

      // Stop ThreadPool if it exists
      if (svc._threadPool)
      {
        svc._threadPool.reset();
      }

      // Clear all dependency tracking data
      svc._dependents.clear();
      svc._pendingDependencies.clear();

      // Clear all API exports to ensure clean state
      svc._apiExports.clear();

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

      // Destroy unique_ptr members
      svc._webhookServer.reset();
      svc._stateStore.reset();
      svc._jsonFileStore.reset();
      svc._configLoader.reset();
      svc._cache.reset();

      svc._config = Config(); // Reset configuration

      // Flush and shutdown logger
      core::Logger::shutdown();

      // Finally, destroy the singleton instance
      IoraService::destroyInstance();
    }
    catch (const std::exception &e)
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
    explicit Plugin(IoraService *service) : _service(service)
    {
      if (!_service)
      {
        throw std::invalid_argument("IoraService instance cannot be null");
      }
    }
    virtual ~Plugin() = default;

    /// \brief Called when the plugin is loaded
    virtual void onLoad(IoraService *service) = 0;

    /// \brief Called before the plugin is unloaded
    virtual void onUnload() = 0;

    IoraService *service() const { return _service; }

    /// \brief Get plugin identity string (for logging and API registration)
    const std::string &getIdentity() const { return _name; }

    /// \brief Require another module as a dependency
    /// This must be called from onLoad(). The required module must already be loaded,
    /// otherwise this call will throw an exception. This registers the dependency
    /// relationship and this plugin will be notified when the dependency is unloaded.
    void require(const std::string &moduleName);

    /// \brief Called when a required dependency is loaded
    /// Override this to handle dependency load events
    virtual void onDependencyLoaded(const std::string &moduleName) {}

    /// \brief Called when a required dependency is unloaded
    /// Override this to handle dependency unload events
    virtual void onDependencyUnloaded(const std::string &moduleName) {}

  private:
    IoraService *_service = nullptr;
    std::vector<std::string> _apiExports;   // APIs this plugin exports
    std::vector<std::string> _dependencies; // Modules this plugin depends on
    std::string _name;                      // Plugin name for identification
    std::string _path;                      // Path to the plugin library
    bool _isLoadingDependencies = false;    // Flag to track dependency loading phase
    friend class IoraService;               // Allow IoraService to access private members
  };

  /// \brief RAII wrapper to automatically shutdown the IoraService
  class AutoServiceShutdown
  {
  public:
    explicit AutoServiceShutdown(iora::IoraService &service) : _svc(service) {}
    ~AutoServiceShutdown() { IoraService::shutdown(); }

  private:
    iora::IoraService &_svc;
  };

  /// \brief Initialises the singleton with a configuration object.
  static void init(const Config &config)
  {
    // First ensure any previous instance is properly cleaned up
    auto instancePtr = getInstancePtr();
    if (instancePtr)
    {
      // If instance exists, shut it down first to ensure clean state
      shutdown();
    }

    // Now get a fresh instance
    auto svcPtr = instance();
    IoraService &svc = *svcPtr;
    svc._config = config;
    svc.applyConfig();
  }

  /// \brief Accessor for the webhook server.
  const std::unique_ptr<network::WebhookServer> &webhookServer() const { return _webhookServer; }

  /// \brief Accessor for the in-memory state store.
  const std::unique_ptr<storage::ConcreteStateStore> &stateStore() const { return _stateStore; }

  /// \brief Accessor for the expiring cache.
  const std::unique_ptr<util::ExpiringCache<std::string, std::string>> &cache() const
  {
    return _cache;
  }

  /// \brief Accessor for the configuration loader.
  const std::unique_ptr<core::ConfigLoader> &configLoader() const { return _configLoader; }

  /// \brief Accessor for the embedded JSON file store.
  const std::unique_ptr<storage::JsonFileStore> &jsonFileStore() const { return _jsonFileStore; }

  /// \brief Get the thread pool instance.
  const std::unique_ptr<core::ThreadPool> &threadPool() const { return _threadPool; }

  /// \brief Factory for creating a JSON file store backed by the given file.
  std::unique_ptr<storage::JsonFileStore> makeJsonFileStore(const std::string &filename) const
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
  void pushEvent(const parsers::Json &event)
  {
    std::string eventId =
      event.contains("eventId") ? event["eventId"].get<std::string>() : "<unknown>";
    std::string eventName =
      event.contains("eventName") ? event["eventName"].get<std::string>() : "<unknown>";
    core::Logger::debug("IoraService: Pushing event (id=" + eventId + ", name=" + eventName +
                        ") to event queue");
    _eventQueue.push(event);
  }

  /// \brief Register a handler for an event by its ID
  void registerEventHandlerById(const std::string &eventId, core::EventQueue::Handler handler)
  {
    core::Logger::info("IoraService: Registering event handler for event ID: " + eventId);
    _eventQueue.onEventId(eventId, std::move(handler));
  }

  /// \brief Register a handler for an event by its name
  void registerEventHandlerByName(const std::string &eventName, core::EventQueue::Handler handler)
  {
    core::Logger::info("IoraService: Registering event handler for event name: " + eventName);
    _eventQueue.onEventName(eventName, std::move(handler));
  }

  /// \brief Provides access to the EventQueue for managing events.
  core::EventQueue &eventQueue() { return _eventQueue; }

  /// \brief Registers a plugin API function that can be called by plugins.
  /// This version maintains plugin association for automatic cleanup.
  template <typename Func> void exportApi(Plugin &plugin, const std::string &name, Func &&func)
  {
    exportApi(plugin.getIdentity(), name, std::forward<Func>(func));
    plugin._apiExports.push_back(name);
  }

  /// \brief Registers an API function with explicit plugin identity (reduces coupling).
  /// Note: Manual cleanup required - no automatic unregistration on plugin unload.
  template <typename Func>
  void exportApi(const std::string &pluginIdentity, const std::string &name, Func &&func)
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
    core::Logger::info("IoraService::exportApi() - Registering plugin API: " + name +
                       " for plugin: " + pluginIdentity);
    std::lock_guard<std::mutex> lock(_apiMutex);
    _apiExports[name] = ApiWrapper(makeStdFunction(std::forward<Func>(func)));
  }

  // Robust function signature deduction and wrapping helpers

  // SFINAE helper to detect if type has operator()
  template <typename T, typename = void> struct has_call_operator : std::false_type
  {
  };

  template <typename T>
  struct has_call_operator<T, std::void_t<decltype(&T::operator())>> : std::true_type
  {
  };

  // Helper for lambdas and functors with operator()
  template <typename Func, typename Ret, typename... Args>
  static std::function<Ret(Args...)> makeStdFunction(Func &&f, Ret (Func::*)(Args...) const)
  {
    return std::function<Ret(Args...)>(std::forward<Func>(f));
  }

  template <typename Func, typename Ret, typename... Args>
  static std::function<Ret(Args...)> makeStdFunction(Func &&f, Ret (Func::*)(Args...))
  {
    return std::function<Ret(Args...)>(std::forward<Func>(f));
  }

  // Helper for function pointers
  template <typename Ret, typename... Args>
  static std::function<Ret(Args...)> makeStdFunction(Ret (*f)(Args...))
  {
    return std::function<Ret(Args...)>(f);
  }

  // Helper for std::function (already in the right format)
  template <typename Ret, typename... Args>
  static std::function<Ret(Args...)> makeStdFunction(const std::function<Ret(Args...)> &f)
  {
    return f;
  }

  template <typename Ret, typename... Args>
  static std::function<Ret(Args...)> makeStdFunction(std::function<Ret(Args...)> &&f)
  {
    return std::move(f);
  }

  // Main makeStdFunction dispatcher for callables with operator()
  template <typename Func>
  static auto makeStdFunction(Func &&f)
    -> std::enable_if_t<has_call_operator<std::decay_t<Func>>::value,
                        decltype(makeStdFunction(std::forward<Func>(f),
                                                 &std::decay_t<Func>::operator()))>
  {
    using func_type = std::decay_t<Func>;
    using signature = decltype(&func_type::operator());
    return makeStdFunction(std::forward<Func>(f), signature{});
  }

  // Type-erased API wrapper for better error reporting
  struct ApiWrapper
  {
    std::any func;
    std::string signature;
    std::type_index type_id;

    // Default constructor needed for unordered_map operator[]
    ApiWrapper() : type_id(typeid(void)) {}

    template <typename FuncSignature>
    ApiWrapper(std::function<FuncSignature> f)
        : func(std::move(f)), signature(typeid(FuncSignature).name()),
          type_id(typeid(std::function<FuncSignature>))
    {
    }

    template <typename FuncSignature>
    std::function<FuncSignature> get(const std::string &apiName) const
    {
      try
      {
        return std::any_cast<std::function<FuncSignature>>(func);
      }
      catch (const std::bad_any_cast &)
      {
        throw std::runtime_error("API signature mismatch for '" + apiName + "'. Expected: " +
                                 typeid(FuncSignature).name() + ", Actual: " + signature);
      }
    }
  };

  // Forward declaration for safe API wrapper
  template <typename FuncSignature> class SafeApiFunction;

  /// \brief Retrieves a registered plugin API as a std::function for repeated
  /// calls.
  /// Throws std::runtime_error if the API is not found or the signature does
  /// not match.
  template <typename FuncSignature>
  std::function<FuncSignature> getExportedApi(const std::string &name)
  {
    std::lock_guard<std::mutex> lock(_apiMutex);
    auto it = _apiExports.find(name);
    if (it == _apiExports.end())
    {
      throw std::runtime_error("API not found: " + name);
    }
    return it->second.get<FuncSignature>(name);
  }

  /// \brief Retrieves a safe wrapper for a plugin API that handles module
  /// unloading gracefully. Uses shared_ptr to prevent dangling pointers.
  /// Returns a shared_ptr to ensure proper lifetime management.
  template <typename FuncSignature>
  std::shared_ptr<SafeApiFunction<FuncSignature>> getExportedApiSafe(const std::string &name)
  {
    auto safeApi = std::make_shared<SafeApiFunction<FuncSignature>>(name, this);
    safeApi->setSelfReference(safeApi);
    return safeApi;
  }

  /// \brief Retrieves the names of all exported APIs.
  std::vector<std::string> getExportedApiNames() const
  {
    std::lock_guard<std::mutex> lock(_apiMutex);
    std::vector<std::string> names;
    for (const auto &kv : _apiExports)
    {
      names.push_back(kv.first);
    }
    return names;
  }

  /// \brief Calls a registered plugin API by name with arguments.
  /// Throws std::runtime_error if the API is not found or the signature does
  /// not match.
  template <typename Ret, typename... Args>
  Ret callExportedApi(const std::string &name, Args &&...args)
  {
    core::Logger::debug("IoraService::callExportedApi() - Calling plugin API: " + name);
    auto func = getExportedApi<Ret(Args...)>(name);
    return func(std::forward<Args>(args)...);
  }

  // --- Fluent API builder class declarations ---
  class RouteBuilder;
  class EventBuilder;

  /// \brief Begin fluent registration of a webhook endpoint.
  RouteBuilder on(const std::string &endpoint);

  /// \brief Begin fluent registration of an event handler.
  EventBuilder onEvent(const std::string &eventId);

  /// \brief Begin fluent registration of an event handler by name.
  EventBuilder onEventName(const std::string &eventName);

  /// \brief Begin fluent registration of an event handler matching a name
  EventBuilder onEventNameMatches(const std::string &eventNamePattern);

  /// \brief Loads a single module from the specified path with security
  /// validation.
  bool loadSingleModule(const std::string &modulePath)
  {
    try
    {
      // Validate path to prevent directory traversal attacks
      if (!validateModulePath(modulePath))
      {
        IORA_LOG_ERROR("Invalid or unsafe module path: " + modulePath);
        return false;
      }

      std::filesystem::path entry(modulePath);
      if (!std::filesystem::exists(entry) || !std::filesystem::is_regular_file(entry))
      {
        IORA_LOG_ERROR("Module path does not exist or is not a file: " + modulePath);
        return false;
      }

      // Additional security check for file extension
      std::string extension = entry.extension().string();
      const std::vector<std::string> allowedExtensions = {".so", ".dll", ".dylib"};
      if (std::find(allowedExtensions.begin(), allowedExtensions.end(), extension) ==
          allowedExtensions.end())
      {
        IORA_LOG_ERROR("Module has unsupported file extension: " + modulePath);
        return false;
      }

      return loadSingleModule(std::filesystem::directory_entry(entry));
    }
    catch (const std::exception &e)
    {
      std::string error_msg = e.what();
      // Only cyclical dependency errors should return false - other dependency issues should
      // throw
      if (error_msg.find("Cyclical dependency detected") != std::string::npos)
      {
        IORA_LOG_ERROR("Failed to load module due to cyclical dependency: " + modulePath + " - " +
                       error_msg);
        return false;
      }

      IORA_LOG_ERROR("Failed to load module: " + modulePath + " - " + error_msg);
      throw; // Re-throw exceptions (including missing dependency errors) to provide detailed
             // error information
    }
  }

  /// \brief Unloads a single module by name
  /// \param pluginName The name of the plugin to unload (e.g., "myplugin.so")
  /// \return true if the module was successfully unloaded, false if it wasn't loaded
  bool unloadSingleModule(const std::string &pluginName)
  {
    std::lock_guard<std::mutex> lock(_loadModulesMutex);
    auto it = _loadedModules.find(pluginName);
    if (it != _loadedModules.end())
    {
      auto &pluginPtr = it->second;
      if (pluginPtr)
      {
        try
        {
          // Notify dependents that this module is about to be unloaded
          notifyDependentsOfUnload(pluginName);

          pluginPtr->onUnload();
          for (auto &apiName : pluginPtr->_apiExports)
          {
            unexportApi(apiName);
          }
          _loadedModules.erase(it); // unique_ptr will delete
          PluginManager::unloadPlugin(pluginName);

          // Clean up dependency tracking data for this plugin
          // Remove entries where this plugin is the dependent (depends on others)
          _pendingDependencies.erase(pluginName);

          // Remove this plugin from other plugins' dependent lists
          for (auto &dependentList : _dependents)
          {
            auto &dependents = dependentList.second;
            dependents.erase(std::remove(dependents.begin(), dependents.end(), pluginName),
                             dependents.end());
          }

          // Note: We don't erase _dependents[pluginName] because other plugins still
          // depend on this one and should be notified when it's reloaded

          IORA_LOG_INFO("Plugin " + pluginName + " unloaded successfully.");

          // Emit module unloaded event
          auto event = parsers::Json::object();
          event["eventId"] = "module_unloaded_" + pluginName;
          event["eventName"] = "module.unload." + pluginName;
          event["moduleName"] = pluginName;
          pushEvent(event);

          return true;
        }
        catch (const std::exception &e)
        {
          IORA_LOG_ERROR("Failed to unload plugin: " + pluginName + " - " + e.what());
        }
      }
    }
    else
    {
      IORA_LOG_ERROR("Plugin not found: " + pluginName);
    }
    return false;
  }

  /// \brief Reloads a module by unloading and loading it again
  /// \param pluginName The name of the plugin to reload (e.g., "myplugin.so")
  /// \return true if the module was successfully reloaded, false otherwise
  bool reloadModule(const std::string &pluginName)
  {
    // Store the plugin path before unloading
    std::string pluginPath;
    {
      std::lock_guard<std::mutex> lock(_loadModulesMutex);
      auto it = _loadedModules.find(pluginName);
      if (it != _loadedModules.end() && it->second)
      {
        pluginPath = it->second->_path;
      }
    }

    // If we couldn't find the plugin path, it's not loaded
    if (pluginPath.empty())
    {
      return false;
    }

    return unloadSingleModule(pluginName) && loadSingleModule(pluginPath);
  }

  /// \brief Check if a module is currently loaded
  bool isModuleLoaded(const std::string &moduleName) const
  {
    std::lock_guard<std::mutex> lock(_loadModulesMutex);
    return isModuleLoadedLocked(moduleName);
  }

protected:
  /// \brief Internal version of isModuleLoaded that assumes lock is already held
  bool isModuleLoadedLocked(const std::string &moduleName) const
  {
    return _loadedModules.find(moduleName) != _loadedModules.end();
  }

public:
  bool unloadAllModules()
  {
    std::lock_guard<std::mutex> lock(_loadModulesMutex);
    bool success = true;

    // Store plugin names for library unloading after plugin destruction
    std::vector<std::string> pluginNames;

    // Call onUnload on all plugins while they're still in place
    for (auto &[name, pluginPtr] : _loadedModules)
    {
      if (pluginPtr)
      {
        pluginNames.push_back(name);
        try
        {
          pluginPtr->onUnload();
          IORA_LOG_INFO("Plugin " + name + " onUnload completed.");
        }
        catch (const std::exception &e)
        {
          IORA_LOG_ERROR("Failed to call onUnload for plugin: " + name + " - " + e.what());
          success = false;
        }
      }
    }

    // Clear all state before plugin destruction
    _loadedModules.clear(); // This will destroy all plugin objects
    _dependents.clear();
    _pendingDependencies.clear();

    // Clear all API exports to ensure clean state
    {
      std::lock_guard<std::mutex> apiLock(_apiMutex);
      _apiExports.clear();
    }

    // Now unload the shared libraries after plugin objects are destroyed
    for (const auto &name : pluginNames)
    {
      try
      {
        PluginManager::unloadPlugin(name);
        IORA_LOG_INFO("Plugin library " + name + " unloaded successfully.");
      }
      catch (const std::exception &e)
      {
        IORA_LOG_ERROR("Failed to unload plugin library: " + name + " - " + e.what());
        success = false;
      }
    }

    // Clear the PluginManager registry to ensure clean state
    PluginManager::unloadAll();

    return success;
  }

  /// \brief Sets the configuration loader for the service.
  void setConfigLoader(std::unique_ptr<core::ConfigLoader> &&loader)
  {
    _configLoader = std::move(loader);
  }

private:
  /// \brief Validates module path to prevent directory traversal and other
  /// security issues.
  static bool validateModulePath(const std::string &path)
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
      std::filesystem::path canonicalPath =
        std::filesystem::canonical(std::filesystem::path(path).parent_path()) /
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
        if (c == '\0' || (c >= 1 && c <= 31 && c != '\t' && c != '\n' && c != '\r'))
        {
          return false;
        }
      }

      return true;
    }
    catch (const std::exception &)
    {
      return false; // Any filesystem error means path is invalid
    }
  }

protected:
  /// \brief Internal singleton storage using shared_ptr for safe lifetime management
  static std::shared_ptr<IoraService> &getInstancePtr()
  {
    static std::shared_ptr<IoraService> instance;
    return instance;
  }

  /// \brief Thread-safe singleton access with shared_ptr for safe lifetime management
  static std::shared_ptr<IoraService> instancePtr()
  {
    static std::mutex instanceMutex;
    std::lock_guard<std::mutex> lock(instanceMutex);

    auto &instance = getInstancePtr();
    if (!instance)
    {
      instance = std::shared_ptr<IoraService>(new IoraService());
    }

    return instance;
  }

  /// \brief Explicitly destroy the singleton instance (for tests only)
  /// WARNING: Only call when no other threads are using the instance
  static void destroyInstance()
  {
    static std::mutex instanceMutex;
    std::lock_guard<std::mutex> lock(instanceMutex);
    getInstancePtr().reset();
  }

  bool loadSingleModule(const std::filesystem::directory_entry &entry)
  {
    std::string pluginName;
    std::string pluginPath;
    bool loadSuccess = false;

    // Critical section: hold mutex only for plugin loading and data structure updates
    {
      std::lock_guard<std::mutex> lock(_loadModulesMutex);
      try
      {
        pluginName = entry.path().filename().string();
        pluginPath = entry.path().string();
        IORA_LOG_INFO("Loading module: " + pluginName);
        loadPlugin(pluginName, pluginPath);

        // Resolve and call the exported loadModule function
        using LoadModuleFunc = Plugin *(*)(iora::IoraService *);
        auto loadModule = resolve<LoadModuleFunc>(pluginName, "loadModule");
        std::unique_ptr<Plugin> pluginInstance(loadModule(this));
        if (pluginInstance)
        {
          pluginInstance->_name = pluginName; // Set the plugin name
          pluginInstance->_path = pluginPath; // Set the plugin path
          try
          {
            pluginInstance->onLoad(this);

            // Only add to _loadedModules if onLoad succeeds
            _loadedModules.insert({pluginName, std::move(pluginInstance)});

            // Notify dependents that this module is now loaded
            notifyDependentsOfLoad(pluginName);

            // Only mark as successful if we reach this point
            loadSuccess = true;
          }
          catch (const std::exception &e)
          {
            // If onLoad fails, the plugin should not be considered loaded
            throw;
          }
        }
        else
        {
          IORA_LOG_ERROR("Module " + pluginName + " did not return a valid instance.");
          return false;
        }
      }
      catch (const std::exception &e)
      {
        IORA_LOG_ERROR("Failed to load module: " + entry.path().string() + " - " + e.what());
        throw; // Re-throw to provide detailed error information to the caller
      }
    } // End critical section - mutex released here

    // Push event after releasing mutex to avoid potential deadlock with event handlers
    // TEMPORARILY DISABLED to test if events are causing the deadlock
    if (false && loadSuccess)
    {
      auto event = parsers::Json::object();
      event["eventId"] = "module_loaded_" + pluginName;
      event["eventName"] = "module.load." + pluginName;
      event["moduleName"] = pluginName;
      event["modulePath"] = pluginPath;
      pushEvent(event);
    }

    return loadSuccess;
  }

  /// \brief Loads all modules configured in the modules config section
  /// Automatically called during initialization if autoLoad is true (default)
  void loadModules()
  {
    if (_modulesPath.empty())
    {
      IORA_LOG_INFO("No modules specified, skipping plugin loading.");
      return;
    }
    IORA_LOG_INFO("Loading modules from: " + _modulesPath);
    std::filesystem::path modulesPath(_modulesPath);
    if (!std::filesystem::exists(modulesPath))
    {
      IORA_LOG_ERROR("Modules path does not exist: " + _modulesPath);
      return;
    }
    if (!std::filesystem::is_directory(modulesPath))
    {
      IORA_LOG_ERROR("Modules path is not a directory: " + _modulesPath);
      return;
    }

    if (_config.modules.modules.has_value() && !_config.modules.modules->empty())
    {
      for (const auto &moduleName : *_config.modules.modules)
      {
        std::filesystem::path modulePath = modulesPath / moduleName;
        if (std::filesystem::exists(modulePath) && std::filesystem::is_regular_file(modulePath))
        {
          loadSingleModule(modulePath.string());
        }
        else
        {
          IORA_LOG_ERROR("Module not found: " + modulePath.string());
        }
      }
      return;
    }
    else
    {
      const std::vector<std::string> supportedExtensions = {".so", ".dll"};
      for (const auto &entry : std::filesystem::directory_iterator(modulesPath))
      {
        if (entry.is_regular_file() &&
            std::find(supportedExtensions.begin(), supportedExtensions.end(),
                      entry.path().extension()) != supportedExtensions.end())
        {
          loadSingleModule(entry);
        }
      }
    }
    IORA_LOG_INFO("Module loading complete.");
  }

  /// \brief Unregisters a plugin API by name.
  /// Throws std::runtime_error if the API is not found.
  void unexportApi(const std::string &name)
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
      IORA_LOG_ERROR("applyConfig: Cannot apply config while service is running");
      throw std::runtime_error("Cannot apply config while service is running");
    }
    // Fill in defaults for any unset config values
    const int DEFAULT_PORT = 8080;
    const char *DEFAULT_STATE_FILE = "state.json";
    const char *DEFAULT_LOG_LEVEL = "info";
    const char *DEFAULT_LOG_FILE = "";
    const bool DEFAULT_LOG_ASYNC = false;
    const int DEFAULT_LOG_RETENTION = 7;
    const char *DEFAULT_LOG_TIME_FORMAT = "%Y-%m-%d %H:%M:%S";

    // Logger: must be initialized first
    auto toLevel = [](const std::string &s)
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
      IORA_LOG_INFO("applyConfig: Logger initialized");
    }
    catch (const std::exception &e)
    {
      IORA_LOG_WARN("applyConfig: Logger already initialized, skipping: " << e.what());
    }

    // Log config values for diagnostics (now logger is ready)
    IORA_LOG_INFO("applyConfig: state.file = " << _config.state.file.value_or("<unset>"));
    IORA_LOG_INFO("applyConfig: log.level = " << _config.log.level.value_or("<unset>"));
    IORA_LOG_INFO("applyConfig: log.file = " << _config.log.file.value_or("<unset>"));
    IORA_LOG_INFO("applyConfig: log.async = " << (_config.log.async.has_value()
                                                    ? (_config.log.async.value() ? "true" : "false")
                                                    : "<unset>"));
    IORA_LOG_INFO(
      "applyConfig: log.retentionDays = " << (_config.log.retentionDays.has_value()
                                                ? std::to_string(_config.log.retentionDays.value())
                                                : "<unset>"));
    IORA_LOG_INFO("applyConfig: log.timeFormat = " << _config.log.timeFormat.value_or("<unset>"));
    IORA_LOG_INFO(
      "applyConfig: server.bindAddress = " << _config.server.bindAddress.value_or("<unset>"));
    IORA_LOG_INFO("applyConfig: server.port = " << (_config.server.port.has_value()
                                                      ? std::to_string(_config.server.port.value())
                                                      : "<unset>"));
    IORA_LOG_INFO(
      "applyConfig: server.tls.certFile = " << _config.server.tls.certFile.value_or("<unset>"));
    IORA_LOG_INFO(
      "applyConfig: server.tls.keyFile = " << _config.server.tls.keyFile.value_or("<unset>"));
    IORA_LOG_INFO(
      "applyConfig: server.tls.caFile = " << _config.server.tls.caFile.value_or("<unset>"));
    IORA_LOG_INFO("applyConfig: server.tls.requireClientCert = "
                  << (_config.server.tls.requireClientCert.has_value()
                        ? (_config.server.tls.requireClientCert.value() ? "true" : "false")
                        : "<unset>"));
    IORA_LOG_INFO(
      "applyConfig: modules.directory = " << _config.modules.directory.value_or("<unset>"));

    // State file
    std::string stateFile = _config.state.file.value_or(DEFAULT_STATE_FILE);
    IORA_LOG_INFO("applyConfig: Creating JsonFileStore at: " << stateFile);
    _jsonFileStore = std::make_unique<storage::JsonFileStore>(stateFile);
    assert(_jsonFileStore && "_jsonFileStore must be initialized after config");
    IORA_LOG_INFO("applyConfig: JsonFileStore created at: " << stateFile);

    // Webhook Server
    std::string bindAddress = _config.server.bindAddress.value_or("0.0.0.0");
    auto port = _config.server.port.value_or(DEFAULT_PORT);
    _webhookServer = std::make_unique<network::WebhookServer>(bindAddress, port);
    IORA_LOG_INFO("applyConfig: Setting webhook server to bind on " << bindAddress << ":" << port);

    // TLS
    bool hasTls = _config.server.tls.certFile.has_value() &&
                  _config.server.tls.keyFile.has_value() &&
                  _config.server.tls.caFile.has_value();
    if (hasTls)
    {
      IORA_LOG_INFO("applyConfig: TLS is enabled");
      network::WebhookServer::TlsConfig tlsCfg;
      tlsCfg.certFile = _config.server.tls.certFile.value_or("");
      tlsCfg.keyFile = _config.server.tls.keyFile.value_or("");
      tlsCfg.caFile = _config.server.tls.caFile.value_or("");
      tlsCfg.requireClientCert = _config.server.tls.requireClientCert.value_or(false);
      IORA_LOG_INFO("applyConfig: Enabling TLS with certFile=" + tlsCfg.certFile +
                    ", keyFile=" + tlsCfg.keyFile + ", caFile=" + tlsCfg.caFile +
                    ", requireClientCert=" + (tlsCfg.requireClientCert ? "true" : "false"));
      _webhookServer->enableTls(tlsCfg);
    }
    else
    {
      IORA_LOG_INFO("applyConfig: TLS is not enabled");
    }

    // Start the webhook server
    IORA_LOG_INFO("applyConfig: Starting webhook server on port: " << port);
    try
    {
      _webhookServer->start();
      IORA_LOG_INFO("applyConfig: Webhook server started successfully");
    }
    catch (const std::exception &e)
    {
      IORA_LOG_ERROR("applyConfig: Failed to start webhook server: " << e.what());
      throw;
    }

    // Thread pool
    std::size_t minThreads = _config.threadPool.minThreads.value_or(1);
    std::size_t maxThreads = _config.threadPool.maxThreads.value_or(
      std::thread::hardware_concurrency() > 0 ? std::thread::hardware_concurrency() : 4);
    std::size_t queueSize = _config.threadPool.queueSize.value_or(maxThreads * 2);
    std::chrono::seconds idleTimeout =
      _config.threadPool.idleTimeoutSeconds.value_or(std::chrono::seconds(60));
    _threadPool =
      std::make_unique<core::ThreadPool>(minThreads, maxThreads, idleTimeout, queueSize);

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
      std::chrono::minutes(1)); // Default flush interval of 1 minute

    if (_config.modules.autoLoad.value_or(true))
    {
      IORA_LOG_INFO("applyConfig: Auto-loading modules is enabled");
      loadModules();
    }
    else
    {
      IORA_LOG_INFO("applyConfig: Auto-loading modules is disabled");
    }

    IORA_LOG_INFO("applyConfig: Configuration applied");

    // Start the webhook server

    _isRunning = true;
  }

  // Implementation of dependency management methods
  /// \brief Registers a dependency relationship between two modules (thread-safe)
  /// \param dependent The module that depends on another module
  /// \param dependency The module that the dependent module requires
  void registerDependency(const std::string &dependent, const std::string &dependency)
  {
    std::lock_guard<std::mutex> lock(_loadModulesMutex);
    registerDependencyLocked(dependent, dependency);
  }

  /// \brief Registers a dependency relationship assuming the mutex is already held
  /// \param dependent The module that depends on another module
  /// \param dependency The module that the dependent module requires
  /// \note PRECONDITION: Caller must hold _loadModulesMutex
  void registerDependencyLocked(const std::string &dependent, const std::string &dependency)
  {
    // PRECONDITION: Caller must hold _loadModulesMutex
#ifdef DEBUG
    // In debug builds, try to detect if mutex is held by attempting a try_lock
    // If try_lock succeeds, we didn't hold the mutex (bad!) - unlock and assert
    if (_loadModulesMutex.try_lock())
    {
      _loadModulesMutex.unlock();
      assert(false && "registerDependencyLocked called without holding _loadModulesMutex");
    }
#endif

    _dependents[dependency].push_back(dependent);

    // Don't use [] operator as it creates entries - use find instead
    auto pluginIt = _loadedModules.find(dependent);
    if (pluginIt != _loadedModules.end() && pluginIt->second)
    {
      pluginIt->second->_dependencies.push_back(dependency);
    }

    // If dependency is not loaded, add to pending
    if (_loadedModules.find(dependency) == _loadedModules.end())
    {
      _pendingDependencies[dependent].push_back(dependency);
    }
  }

  void notifyDependentsOfLoad(const std::string &moduleName)
  {
    // This is called after a module is loaded - notify dependents synchronously
    // PRECONDITION: Caller must hold _loadModulesMutex
#ifdef DEBUG
    // In debug builds, try to detect if mutex is held by attempting a try_lock
    // If try_lock succeeds, we didn't hold the mutex (bad!) - unlock and assert
    if (_loadModulesMutex.try_lock())
    {
      _loadModulesMutex.unlock();
      assert(false && "notifyDependentsOfLoad called without holding _loadModulesMutex");
    }
#endif

    auto it = _dependents.find(moduleName);
    if (it != _dependents.end())
    {
      for (const auto &dependent : it->second)
      {
        auto pluginIt = _loadedModules.find(dependent);
        if (pluginIt != _loadedModules.end() && pluginIt->second)
        {
          try
          {
            pluginIt->second->onDependencyLoaded(moduleName);
          }
          catch (const std::exception &e)
          {
            IORA_LOG_ERROR("Plugin " + dependent + " threw exception in onDependencyLoaded(" +
                           moduleName + "): " + e.what());
          }
        }

        // Remove from pending dependencies
        auto pendingIt = _pendingDependencies.find(dependent);
        if (pendingIt != _pendingDependencies.end())
        {
          auto &pending = pendingIt->second;
          pending.erase(std::remove(pending.begin(), pending.end(), moduleName), pending.end());
        }
      }
    }
  }

  void notifyDependentsOfUnload(const std::string &moduleName)
  {
    // This is called before a module is unloaded - notify dependents synchronously
    // PRECONDITION: Caller must hold _loadModulesMutex
#ifdef DEBUG
    // In debug builds, try to detect if mutex is held by attempting a try_lock
    // If try_lock succeeds, we didn't hold the mutex (bad!) - unlock and assert
    if (_loadModulesMutex.try_lock())
    {
      _loadModulesMutex.unlock();
      assert(false && "notifyDependentsOfUnload called without holding _loadModulesMutex");
    }
#endif

    auto it = _dependents.find(moduleName);
    if (it != _dependents.end())
    {
      for (const auto &dependent : it->second)
      {
        auto pluginIt = _loadedModules.find(dependent);
        if (pluginIt != _loadedModules.end() && pluginIt->second)
        {
          try
          {
            pluginIt->second->onDependencyUnloaded(moduleName);
          }
          catch (const std::exception &e)
          {
            IORA_LOG_ERROR("Plugin " + dependent + " threw exception in onDependencyUnloaded(" +
                           moduleName + "): " + e.what());
          }
        }

        // Add back to pending dependencies since the dependency is being unloaded
        _pendingDependencies[dependent].push_back(moduleName);
      }
    }
  }

  // Note: Cycle detection removed - TOML config is responsible for correct loading order

private:
  // For main thread blocking/termination
  std::mutex _terminationMutex;
  std::condition_variable _terminationCv;
  bool _terminated = false;

  // Plugin dependency management
  std::unordered_map<std::string, std::vector<std::string>>
    _dependents; // module -> list of modules that depend on it
  std::unordered_map<std::string, std::vector<std::string>>
    _pendingDependencies; // module -> list of dependencies not yet loaded
  std::vector<std::string>
    _loadOrder; // Order in which modules should be loaded to satisfy dependencies

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
  core::EventQueue _eventQueue{4}; // Default to 4 worker threads
  std::unordered_map<std::string, ApiWrapper> _apiExports;
  mutable std::mutex _loadModulesMutex; // Mutex for thread-safe module loading
  mutable std::mutex _apiMutex;
  std::atomic<bool> _isRunning{false};

  /// \brief Holds the merged configuration (CLI, TOML, defaults).
  Config _config;
};

class IoraService::RouteBuilder
{
public:
  RouteBuilder(network::WebhookServer &server, const std::string &endpoint)
      : _server(server), _endpoint(endpoint)
  {
  }

  void handleJson(const network::WebhookServer::JsonHandler &handler)
  {
    _server.onJsonPost(_endpoint, handler);
  }

private:
  network::WebhookServer &_server;
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

  EventBuilder(core::EventQueue &queue, const std::string &eventId, EventType type)
      : _queue(queue), _eventId(eventId), _eventType(type)
  {
  }

  void handle(const core::EventQueue::Handler &handler)
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
  core::EventQueue &_queue;
  std::string _eventId;
  EventType _eventType = EventType::ID; // Default to ID type
};

inline IoraService::RouteBuilder IoraService::on(const std::string &endpoint)
{
  // Use the accessor to ensure runtime check
  return RouteBuilder(*_webhookServer, endpoint);
}

inline IoraService::EventBuilder IoraService::onEvent(const std::string &eventId)
{
  return EventBuilder(_eventQueue, eventId, EventBuilder::EventType::ID);
}

inline IoraService::EventBuilder IoraService::onEventName(const std::string &eventName)
{
  return EventBuilder(_eventQueue, eventName, EventBuilder::EventType::NAME);
}

inline IoraService::EventBuilder
IoraService::onEventNameMatches(const std::string &eventNamePattern)
{
  return EventBuilder(_eventQueue, eventNamePattern, EventBuilder::EventType::NAME_MATCHES);
}

/// \brief Thread-safe wrapper for exported API functions that handles module unloading gracefully.
///
/// Features:
/// - **Thread Safety**: Multiple threads can safely call the API concurrently
/// - **Event-Based Caching**: Optimal performance - only validates when modules are
/// unloaded/reloaded
/// - **Crash Prevention**: Never calls invalid function pointers, throws clear exceptions instead
/// - **Auto-Recovery**: Automatically works again when modules are reloaded
///
/// Thread Safety Implementation:
/// - Uses atomic<bool> for the validity flag
/// - Mutex protects the cached function pointer updates
/// - Double-checked locking pattern for performance
/// - Event handlers use weak_ptr to prevent dangling pointers
/// - Uses weak_ptr self-reference for safe event handling
template <typename R, typename... Args> class IoraService::SafeApiFunction<R(Args...)>
{
private:
  mutable std::function<R(Args...)> cachedFunc;
  mutable std::atomic<bool> valid{false};
  mutable std::mutex cacheMutex; // Protects cachedFunc updates
  std::string apiName;
  std::string moduleName;
  IoraService *service;
  mutable std::atomic<bool> eventHandlerRegistered{false};
  mutable std::weak_ptr<SafeApiFunction<R(Args...)>> selfReference;

  /// \brief Find module name from API name by checking all loaded modules
  std::string findModuleNameForApi(const std::string &apiName) const
  {
    IORA_LOG_INFO("MUTEX DEBUG: SafeApiFunction attempting to acquire _loadModulesMutex for API: " +
                  apiName);
    std::lock_guard<std::mutex> lock(service->_loadModulesMutex);
    IORA_LOG_INFO("MUTEX DEBUG: SafeApiFunction acquired _loadModulesMutex for API: " + apiName);
    auto result = findModuleNameForApiLocked(apiName);
    IORA_LOG_INFO("MUTEX DEBUG: SafeApiFunction releasing _loadModulesMutex for API: " + apiName);
    return result;
  }

  std::string findModuleNameForApiLocked(const std::string &apiName) const
  {
    // Extract the prefix from API name (e.g., "testplugin.add" -> "testplugin")
    size_t dotPos = apiName.find('.');
    std::string apiPrefix = (dotPos != std::string::npos) ? apiName.substr(0, dotPos) : apiName;

    // Look for a loaded module whose name starts with the API prefix
    for (const auto &[moduleName, pluginPtr] : service->_loadedModules)
    {
      if (pluginPtr && moduleName.find(apiPrefix) == 0)
      {
        // Check if this module actually exports this API
        for (const auto &exportedApi : pluginPtr->_apiExports)
        {
          if (exportedApi == apiName)
          {
            return moduleName; // Found the right module
          }
        }
      }
    }

    // Fallback: assume module name is prefix + ".so"
    return apiPrefix + ".so";
  }

  /// \brief Register event handler safely using weak_ptr
  void registerEventHandler() const
  {
    if (!eventHandlerRegistered.exchange(true))
    {
      // Escape the module name for regex (dots need to be escaped)
      std::string escapedModuleName = moduleName;
      size_t pos = 0;
      while ((pos = escapedModuleName.find('.', pos)) != std::string::npos)
      {
        escapedModuleName.replace(pos, 1, "\\.");
        pos += 2; // Move past the inserted escape sequence
      }

      // Use weak_ptr to avoid dangling pointer in event handler.
      // Use the self-reference set by getExportedApiSafe()
      auto wp = selfReference;

      // Listen for module unload/reload events for this specific module
      service->onEventNameMatches("^module\\.(unload|reload)\\." + escapedModuleName + "$")
        .handle(
          [wp](const parsers::Json &event)
          {
            // Use weak_ptr to safely check if SafeApiFunction still exists
            if (auto sp = wp.lock())
            {
              // Thread-safe invalidation of cache
              sp->valid.store(false);
            }
            // If weak_ptr expired, SafeApiFunction was destroyed - handler is safe
          });
    }
  }

public:
  /// \brief Constructor that defers event registration until shared_ptr is created
  SafeApiFunction(const std::string &name, IoraService *svc) : apiName(name), service(svc)
  {
    // Find the actual module name for this API
    moduleName = findModuleNameForApi(name);
    // Event handler registration is deferred until first use
  }

  /// \brief Set the self-reference weak_ptr (called by getExportedApiSafe)
  void setSelfReference(std::weak_ptr<SafeApiFunction<R(Args...)>> ref) { selfReference = ref; }

  /// \brief Function call operator - validates module and calls API (thread-safe)
  R operator()(Args... args) const
  {
    // Ensure event handler is registered (lazy initialization)
    registerEventHandler();

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
      throw std::runtime_error("API '" + apiName + "' unavailable: module '" + moduleName +
                               "' not loaded");
    }

    // Refresh the cached function
    try
    {
      cachedFunc = service->getExportedApi<R(Args...)>(apiName);
      valid.store(true);
      return cachedFunc(args...);
    }
    catch (const std::exception &e)
    {
      valid.store(false);
      throw std::runtime_error("Failed to refresh API '" + apiName + "': " + e.what());
    }
  }

  /// \brief Check if the API is currently available
  bool isAvailable() const { return service->isModuleLoaded(moduleName); }

  /// \brief Get the module name for this API
  const std::string &getModuleName() const { return moduleName; }

  /// \brief Get the API name
  const std::string &getApiName() const { return apiName; }
};

using IoraPlugin = IoraService::Plugin;
#define IORA_DECLARE_PLUGIN(PluginType)                                                            \
  extern "C" iora::IoraPlugin *loadModule(iora::IoraService *service)                              \
  {                                                                                                \
    try                                                                                            \
    {                                                                                              \
      PluginType *instance = new PluginType(service);                                              \
      return instance;                                                                             \
    }                                                                                              \
    catch (const std::exception &e)                                                                \
    {                                                                                              \
      iora::core::Logger::error("Plugin initialization failed: " + std::string(e.what()));         \
      return nullptr;                                                                              \
    }                                                                                              \
  }

// Implementation of Plugin::require() method
inline void IoraService::Plugin::require(const std::string &moduleName)
{
  if (!_service)
  {
    throw std::runtime_error("Plugin::require() called with null service");
  }

  // Simply check if the required module is loaded
  bool isLoaded = _service->isModuleLoadedLocked(moduleName);
  if (!isLoaded)
  {
    // Module not loaded - throw exception. The TOML config must ensure proper loading order
    throw std::runtime_error(
      "Required dependency '" + moduleName +
      "' is not loaded. Ensure modules are loaded in the correct order via configuration.");
  }

  // Register this dependency relationship for tracking
  // Use locked version since we're called from onLoad() which is called from loadSingleModule()
  // which already holds _loadModulesMutex
  _service->registerDependencyLocked(_name, moduleName);

  // Module is loaded, notify this plugin
  try
  {
    onDependencyLoaded(moduleName);
  }
  catch (const std::exception &e)
  {
    IORA_LOG_ERROR("Plugin " + _name + " threw exception in onDependencyLoaded(" + moduleName +
                   "): " + e.what());
  }
}

} // namespace iora
