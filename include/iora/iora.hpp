// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "core/config_loader.hpp"
#include "core/metrics.hpp"
#include "core/event_queue.hpp"
#include "core/logger.hpp"
#include "core/plugin_loader.hpp"
#include "core/service_registry.hpp"
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
#include <unordered_set>

#define IORA_DEFAULT_CONFIG_FILE_PATH "/etc/iora.conf.d/iora.cfg"

namespace iora
{

/// \brief Non-template host-side base so IoraService can clear a heterogeneous
/// per-module registry of SafeApiFunction wrappers before dlclose (DP-B).
///
/// invalidateAndClearCache() takes the wrapper's cacheMutex and destroys its
/// cached plugin std::function while the plugin .so is still mapped. Because
/// operator() invokes the cached function UNDER cacheMutex, this clear also waits
/// out any in-flight invoke of that wrapper (DP-CACHEMUTEX-SERIALIZES), so no
/// counter/drain is needed. The unloader calls this with _loadModulesMutex
/// RELEASED (DP-CLEAR-OFF-LOADMUTEX) to avoid a _loadModulesMutex->cacheMutex
/// edge that would cycle with operator()'s cacheMutex->_loadModulesMutex order.
/// The vtable of any concrete SafeApiFunction is host-resident because
/// getExportedApiSafe is only ever called from host TUs (DP-F/host-only).
struct ISafeApiClearable
{
  virtual ~ISafeApiClearable() = default;
  /// \brief Invalidate the wrapper and destroy its cached std::function (under
  /// cacheMutex, .so still mapped). noexcept.
  virtual void invalidateAndClearCache() noexcept = 0;
};

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
      std::optional<int> compressAfterDays;
    } log;
    struct ThreadPool
    {
      std::optional<std::size_t> minThreads;
      std::optional<std::size_t> maxThreads;
      std::optional<std::size_t> queueSize;
      std::optional<std::chrono::seconds> idleTimeoutSeconds;
    } threadPool;

    /// \brief Toggles for optional IoraService subsystems.
    /// Unset fields resolve to `true` via `.value_or(true)` in applyConfig(),
    /// preserving the legacy behavior of constructing every subsystem.
    /// Hosts that do not need a subsystem (e.g. edge_proxy does not need
    /// jsonFileStore/stateStore/expiringCache/modules) set the flag to `false`
    /// via TOML or CLI to skip construction.
    /// Precedence: CLI > TOML > default. Enforced by call order in main():
    /// parseCliArgs() must run before parseTomlConfig(); parseTomlConfig()
    /// writes only when !has_value(), so CLI (which sets directly) wins.
    struct FeaturesConfig
    {
      std::optional<bool> server;
      std::optional<bool> jsonFileStore;
      std::optional<bool> stateStore;
      std::optional<bool> expiringCache;
      std::optional<bool> modules;
    } features;

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

      // Stop and destroy the webhook server BEFORE unloading modules.
      // Plugins may have registered route handlers (std::function callbacks)
      // on the webhook server. If modules are unloaded first, those callbacks
      // become dangling pointers into unmapped .so memory.
      if (svc._webhookServer)
      {
        svc._webhookServer->stop();
        svc._webhookServer.reset();
      }

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

      // Destroy remaining unique_ptr members
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

  /// \brief Get the global MetricsRegistry singleton.
  /// Available before init() and during shutdown (function-local static).
  core::MetricsRegistry &metrics() { return core::MetricsRegistry::instance(); }

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
    // Check-then-insert must be atomic under _apiMutex: reading _apiExports
    // outside the lock is a data race with concurrent exportApi/unexportApi and a
    // TOCTOU on the duplicate check.
    std::lock_guard<std::mutex> lock(_apiMutex);
    if (_apiExports.find(name) != _apiExports.end())
    {
      core::Logger::error("IoraService::exportApi() - Plugin API already registered: " + name);
      throw std::runtime_error("Plugin API already registered: " + name);
    }
    core::Logger::info("IoraService::exportApi() - Registering plugin API: " + name +
                       " for plugin: " + pluginIdentity);
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
    // HOST-ONLY (DP-G/DP-H-hostonly): a SafeApiFunction created in a plugin TU has
    // its vtable + shared_ptr control block resident in the plugin .so; if it (or
    // the service's weak_ptr) outlives the plugin's dlclose, destroying it invokes
    // an unmapped manager -> the exact destructor UAF this fix prevents. We cannot
    // detect a plugin caller in general, but the one cheaply-detectable and most
    // likely case is a plugin calling this from onLoad (which runs while this
    // thread holds _loadModulesMutex): reject it loudly rather than hand back a
    // wrapper that crashes at shutdown.
    if (ownsLoadModulesMutex())
    {
      throw std::runtime_error(
        "getExportedApiSafe() is host-only and must not be called during module load "
        "(e.g. from a plugin onLoad): the wrapper's vtable would live in the plugin .so "
        "and use-after-dlclose. Resolve the API from the host after load instead.");
    }
    // Sole factory (DP-G): the ctor is private and registration is intrinsic, so
    // no SafeApiFunction can exist unregistered (which would leave its cache
    // uncleared before dlclose). make_shared cannot reach the private ctor.
    std::shared_ptr<SafeApiFunction<FuncSignature>> safeApi(
      new SafeApiFunction<FuncSignature>(name, this));
    safeApi->setSelfReference(safeApi);
    registerSafeApi(safeApi->getModuleName(), std::weak_ptr<ISafeApiClearable>(safeApi));
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
    // LoadModulesGuard keeps ownsLoadModulesMutex() in sync with the lock across
    // the release/re-acquire window used for the off-lock cache clear.
    LoadModulesGuard guard(_loadModulesMutex);

    if (_loadedModules.find(pluginName) == _loadedModules.end())
    {
      IORA_LOG_ERROR("Plugin not found: " + pluginName);
      return false;
    }
    if (isModuleUnloadingLocked(pluginName))
    {
      // Another unloader already owns the claim; do not re-tear-down.
      return false;
    }

    // Claim the module: new operator() calls now observe it as "not loaded" and
    // throw, and a concurrent same-name load/unload fails fast.
    _apiUnloadingModules.insert(pluginName);

    // Clear every registered wrapper's cache with _loadModulesMutex RELEASED. Each
    // invalidateAndClearCache takes the wrapper's cacheMutex — which serializes
    // against an in-flight invoke (operator() invokes under cacheMutex) and
    // destroys the plugin std::function while the .so is still mapped — and
    // clearing off _loadModulesMutex avoids the _loadModulesMutex->cacheMutex
    // cycle with operator()'s slow path. Restore the claim on any throw
    // (snapshotSafeApis can throw bad_alloc; guard.lock() can throw system_error)
    // so a failure does not brick the module as permanently "unloading".
    try
    {
      guard.unlock();
      clearSafeApiCaches(pluginName);
      guard.lock();
    }
    catch (...)
    {
      if (!guard.ownsLock())
      {
        guard.lock();
      }
      openGate(pluginName);
      throw;
    }

    // Host-side teardown (onUnload/unexport/unregister/erase/dependency cleanup/
    // prune), THEN dlclose — dlclose runs only after every host-side destroy, while
    // the .so is still mapped. teardownModuleHostSideLocked returns false (no
    // dlclose) if the module vanished across the release/re-acquire (claim blocks
    // that, but bail safely if so) or if onUnload threw (leave it as the original
    // did). The claim is released regardless.
    const bool ok = teardownModuleHostSideLocked(pluginName, /*notifyDependents=*/true);
    if (ok)
    {
      PluginManager::unloadPlugin(pluginName); // dlclose AFTER host-side teardown
    }
    openGate(pluginName);

    if (ok)
    {
      IORA_LOG_INFO("Plugin " + pluginName + " unloaded successfully.");
      // Emit module unloaded event
      auto event = parsers::Json::object();
      event["eventId"] = "module_unloaded_" + pluginName;
      event["eventName"] = "module.unload." + pluginName;
      event["moduleName"] = pluginName;
      pushEvent(event);
    }
    return ok;
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
    // A module claimed unloading (DP-E) reports NOT loaded so the API gate,
    // isModuleLoaded(), and Plugin::require() all agree it is unavailable during
    // the unload/claim window, even though its entry is still in _loadedModules until
    // teardown completes.
    if (!_apiUnloadingModules.empty() &&
        _apiUnloadingModules.find(moduleName) != _apiUnloadingModules.end())
    {
      return false;
    }
    return _loadedModules.find(moduleName) != _loadedModules.end();
  }

public:
  bool unloadAllModules()
  {
    LoadModulesGuard guard(_loadModulesMutex);
    bool success = true;

    // Claim every (not-already-unloading) module and snapshot the names to tear
    // down, all while holding _loadModulesMutex.
    std::vector<std::string> names;
    for (auto &kv : _loadedModules)
    {
      const std::string &name = kv.first;
      if (isModuleUnloadingLocked(name))
      {
        continue; // a concurrent single-unload owns this claim
      }
      _apiUnloadingModules.insert(name);
      names.push_back(name);
    }

    // Clear all wrapper caches with _loadModulesMutex RELEASED (see
    // unloadSingleModule): each clear serializes against in-flight invokes via
    // cacheMutex and frees the plugin std::function before dlclose. Restore all
    // claims on any throw so a failure does not brick modules as "unloading".
    try
    {
      guard.unlock();
      for (const auto &name : names)
      {
        clearSafeApiCaches(name);
      }
      guard.lock();
    }
    catch (...)
    {
      if (!guard.ownsLock())
      {
        guard.lock();
      }
      for (const auto &name : names)
      {
        openGate(name);
      }
      throw;
    }

    // TWO-PASS teardown over ONLY the claimed names. Pass 1: host-side teardown for
    // EVERY module (onUnload/unexport/unregister/erase/dependency cleanup/prune) —
    // NO dlclose. Pass 2: dlclose the modules that were erased. This guarantees no
    // module's onUnload runs after a sibling's .so has been dlclosed (the original
    // batch-unloadAll() ordering, restored). We NEVER PluginManager::unloadAll() or
    // blanket-clear the dependency maps: that would dlclose/wipe a module this call
    // did NOT claim (one a concurrent unloadSingleModule owns, or one loaded during
    // the release window). Orphaned PluginManager entries from failed loads are
    // cleaned up at the source in loadSingleModule.
    std::vector<std::string> toDlclose;
    toDlclose.reserve(names.size());
    for (const auto &name : names)
    {
      // notifyDependents=false for batch unload (everything is going away; matches
      // the original unloadAllModules, which did not notify dependents).
      if (teardownModuleHostSideLocked(name, /*notifyDependents=*/false))
      {
        toDlclose.push_back(name);
      }
      else
      {
        success = false; // present-but-onUnload-threw, or already gone
      }
    }
    for (const auto &name : toDlclose)
    {
      PluginManager::unloadPlugin(name); // dlclose only AFTER every host-side teardown
      IORA_LOG_INFO("Plugin library " + name + " unloaded successfully.");
    }
    for (const auto &name : names)
    {
      openGate(name);
    }

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

public:
#if defined(IORA_CORE_SHARED) || defined(IORA_CORE_BUILDING)
  /// \brief Internal singleton storage using shared_ptr for safe lifetime management
  static std::shared_ptr<IoraService> &getInstancePtr();
  /// \brief Thread-safe singleton access with shared_ptr for safe lifetime management
  static std::shared_ptr<IoraService> instancePtr();
  /// \brief Explicitly destroy the singleton instance (for tests only)
  /// WARNING: Only call when no other threads are using the instance
  static void destroyInstance();
#else
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
#endif

protected:
  bool loadSingleModule(const std::filesystem::directory_entry &entry)
  {
    std::string pluginName;
    std::string pluginPath;
    bool loadSuccess = false;
    // True once loadPlugin() has registered this .so in PluginManager for THIS
    // call, so the failure-path cleanup only unregisters an entry we own — NOT one
    // a concurrent load owns (a "Plugin already loaded" throw from loadPlugin must
    // never dlclose the other loader's live module).
    bool pluginRegistered = false;

    // Critical section: hold mutex only for plugin loading and data structure updates
    {
      // LoadModulesGuard (not a bare lock_guard) so ownsLoadModulesMutex() is
      // true across onLoad(): a plugin whose onLoad calls getExportedApiSafe is
      // then REJECTED (getExportedApiSafe throws) — its wrapper's vtable would live
      // in the plugin .so and use-after-dlclose (DP-F host-only enforcement).
      LoadModulesGuard loadGuard(_loadModulesMutex);
      try
      {
        pluginName = entry.path().filename().string();
        pluginPath = entry.path().string();

        // Fail-fast if this module name is mid-unload (claimed): loading over a
        // an in-progress unload would drop the fresh instance (map insert is a no-op on
        // an existing key) and corrupt the module map across the release/re-acquire window
        // (DP-E). This directory_entry overload is the single insertion point, so
        // it covers reloadModule and batch loadModules().
        if (isModuleUnloadingLocked(pluginName))
        {
          IORA_LOG_ERROR("Cannot load '" + pluginName + "': an unload is in progress.");
          return false;
        }

        IORA_LOG_INFO("Loading module: " + pluginName);
        loadPlugin(pluginName, pluginPath);
        pluginRegistered = true; // we now own the PluginManager entry for this name

        // Resolve and call the exported loadModule function
        using LoadModuleFunc = Plugin *(*)(iora::IoraService *);
        auto loadModule = resolve<LoadModuleFunc>(pluginName, "loadModule");
        std::unique_ptr<Plugin> pluginInstance(loadModule(this));
        if (pluginInstance)
        {
          pluginInstance->_name = pluginName; // Set the plugin name
          pluginInstance->_path = pluginPath; // Set the plugin path
          // Snapshot of the names onLoad exported, captured the moment onLoad
          // returns and BEFORE the _loadedModules insert. This is the failure-path
          // teardown's authoritative source: if the insert itself throws (rehash
          // bad_alloc), the moved-from Plugin object (the braced value_type
          // temporary) is destroyed during unwinding and is unreachable from BOTH
          // pluginInstance (null) and _loadedModules (insert had no effect), so the
          // exported names cannot be recovered from the object anymore. (cpp17 M1)
          std::vector<std::string> exportedNames;
          try
          {
            pluginInstance->onLoad(this);
            exportedNames = pluginInstance->_apiExports; // onLoad succeeded

            // Only add to _loadedModules if onLoad succeeds
            _loadedModules.insert({pluginName, std::move(pluginInstance)});

            // Notify dependents that this module is now loaded
            notifyDependentsOfLoad(pluginName);

            // Only mark as successful if we reach this point
            loadSuccess = true;
          }
          catch (const std::exception &)
          {
            // onLoad (or the subsequent insert/notify) failed AFTER the plugin may
            // have exported APIs / registered ServiceRegistry entries. Those hold
            // plugin-resident std::functions / objects; tear them down HOST-SIDE now
            // — while the plugin object and its .so are still mapped — BEFORE the
            // outer catch dlcloses. Otherwise they dangle into the unmapped .so and
            // fault at the next call or at ~IoraService (_apiExports.clear()). (C1)
            //
            // Source the exported names: onLoad-throw -> the still-owned
            // pluginInstance (exportedNames not yet captured); onLoad-success then
            // insert/notify-throw -> the exportedNames snapshot (the object may be
            // gone). This covers the insert-throw sub-case (cpp17 M1).
            // Source the exported names from the still-owned object, else the
            // pre-insert snapshot. Each unexportApi is best-effort (it throws on a
            // not-found name): a missing name must not skip the rest of the teardown
            // (unregister/erase) and leak an object into the .so about to be dlclosed.
            const std::vector<std::string> &namesToUnexport =
              pluginInstance ? pluginInstance->_apiExports : exportedNames;
            for (auto &apiName : namesToUnexport)
            {
              try
              {
                unexportApi(apiName); // destroys the plugin std::function (.so mapped)
              }
              catch (const std::exception &)
              {
              }
            }
            ServiceRegistry::unregisterModule(pluginName);
            auto lit = _loadedModules.find(pluginName);
            if (lit != _loadedModules.end())
            {
              _loadedModules.erase(lit); // ~Plugin while the .so is still mapped
            }
            throw; // outer catch runs PluginManager::unloadPlugin (dlclose) after this
          }
        }
        else
        {
          IORA_LOG_ERROR("Module " + pluginName + " did not return a valid instance.");
          // We registered this .so above; remove OUR entry so a failed load does
          // not leave an orphaned _plugins entry ("already loaded" on retry). This
          // source-level fix lets unloadAll* avoid a blanket
          // PluginManager::unloadAll() (which would dlclose modules it never
          // claimed — a concurrent-unload UAF).
          if (pluginRegistered)
          {
            PluginManager::unloadPlugin(pluginName);
          }
          return false;
        }
      }
      catch (const std::exception &e)
      {
        IORA_LOG_ERROR("Failed to load module: " + entry.path().string() + " - " + e.what());
        // Same source-level cleanup on any load failure AFTER we registered the
        // entry (onLoad threw, resolve failed, etc.). Guarded by pluginRegistered
        // so a "Plugin already loaded" throw from loadPlugin() — where the entry
        // belongs to a CONCURRENT load — never dlcloses that live module.
        if (pluginRegistered)
        {
          PluginManager::unloadPlugin(pluginName);
        }
        throw; // Re-throw to provide detailed error information to the caller
      }
    } // End critical section - mutex released here

    // Note: no module.load event is emitted (unlike module.unload). SafeApiFunction
    // only reacts to module.(unload|reload); no in-repo consumer subscribes to
    // module.load. If load notifications are ever needed, add them here.
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
    const int DEFAULT_LOG_COMPRESS = 0; // 0 = off (compress files older than N days)
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
    int logCompress = _config.log.compressAfterDays.value_or(DEFAULT_LOG_COMPRESS);
    try
    {
      core::Logger::init(toLevel(logLevel), logFile, logAsync, logRetention, logTimeFormat,
                         logCompress);
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
    IORA_LOG_INFO("applyConfig: log.compressAfterDays = "
                  << (_config.log.compressAfterDays.has_value()
                        ? std::to_string(_config.log.compressAfterDays.value())
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

    // State file (JsonFileStore) — gated by features.jsonFileStore
    if (_config.features.jsonFileStore.value_or(true))
    {
      std::string stateFile = _config.state.file.value_or(DEFAULT_STATE_FILE);
      IORA_LOG_INFO("applyConfig: Creating JsonFileStore at: " << stateFile);
      _jsonFileStore = std::make_unique<storage::JsonFileStore>(stateFile);
      IORA_LOG_INFO("applyConfig: JsonFileStore created at: " << stateFile);
    }
    else
    {
      IORA_LOG_INFO("applyConfig: JsonFileStore disabled via features.jsonFileStore=false");
    }

    // Webhook Server — gated by features.server
    if (_config.features.server.value_or(true))
    {
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
    }
    else
    {
      IORA_LOG_INFO("applyConfig: WebhookServer disabled via features.server=false");
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

    // State store — gated by features.stateStore
    if (_config.features.stateStore.value_or(true))
    {
      _stateStore = std::make_unique<storage::ConcreteStateStore>();
    }
    else
    {
      IORA_LOG_INFO("applyConfig: StateStore disabled via features.stateStore=false");
    }

    // Expiring cache — gated by features.expiringCache
    if (_config.features.expiringCache.value_or(true))
    {
      _cache = std::make_unique<util::ExpiringCache<std::string, std::string>>(
        std::chrono::minutes(1)); // Default flush interval of 1 minute
    }
    else
    {
      IORA_LOG_INFO("applyConfig: ExpiringCache disabled via features.expiringCache=false");
    }

    // Module loader — gated by features.modules (outer); inner autoLoad preserved.
    if (_config.features.modules.value_or(true))
    {
      if (_config.modules.autoLoad.value_or(true))
      {
        IORA_LOG_INFO("applyConfig: Auto-loading modules is enabled");
        loadModules();
      }
      else
      {
        IORA_LOG_INFO("applyConfig: Auto-loading modules is disabled");
      }
    }
    else
    {
      IORA_LOG_INFO("applyConfig: Module loader disabled via features.modules=false");
    }

    IORA_LOG_INFO("applyConfig: Configuration applied");

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

  // --- SafeApiFunction clear-before-dlclose machinery (tracker 2026-09-07-1,
  // architecture/iora/safe_api_function_drain.json). Fixes the use-after-dlclose
  // in SafeApiFunction: a cached plugin std::function (manager resident in the
  // plugin .so text) outliving dlclose (destructor UAF), and an operator()
  // invoking it while a concurrent unload dlcloses (concurrent-call UAF).
  //
  // Design (zero per-call cost): operator() invokes the cached function UNDER
  // cacheMutex, exactly as before. On unload the service (a) CLAIMS the module so
  // new calls are rejected, then (b) with _loadModulesMutex RELEASED, clears every
  // registered wrapper's cache under that wrapper's cacheMutex — which both frees
  // the plugin std::function before dlclose AND, via cacheMutex, waits out any
  // in-flight invoke of that wrapper — then (c) re-acquires and tears down/dlclose.
  //
  // Lock order (the ONLY nestings): operator() slow path takes cacheMutex ->
  // _loadModulesMutex -> _apiMutex. The unload CLEAR takes cacheMutex with
  // _loadModulesMutex NOT held (this is what avoids a _loadModulesMutex->cacheMutex
  // edge cycling with operator()'s cacheMutex->_loadModulesMutex order — the exact
  // deadlock a naive clear-under-_loadModulesMutex would hit). _apiCallGuard is a
  // leaf guarding only the registry (snapshot + registration).
  mutable std::mutex _apiCallGuard;
  // Modules currently unloading (claim). Guarded by _loadModulesMutex. Gates ALL
  // same-name module-map mutations: operator()/isModuleLoadedLocked report NOT
  // loaded, load/reload fail-fast, a second unload no-ops.
  std::unordered_set<std::string> _apiUnloadingModules;
  // Live SafeApiFunction wrappers per module, for clear-before-dlclose. Guarded by
  // the LEAF _apiCallGuard so registration is safe from a plugin onLoad (which
  // holds _loadModulesMutex). SHUTDOWN PRECONDITION: this map is destroyed with the
  // IoraService (destroyInstance) off _apiCallGuard, so — like the rest of the
  // service — no thread may call getExportedApiSafe or (un)loadModule concurrently
  // with service destruction (the documented destroyInstance() precondition).
  std::unordered_map<std::string, std::vector<std::weak_ptr<ISafeApiClearable>>> _safeApiRegistry;

public:
  /// \brief Whether this thread currently holds _loadModulesMutex, so
  /// getExportedApiSafe can REJECT (throw on) a call made from a plugin onLoad
  /// (host-only enforcement — a plugin-resident wrapper would use-after-dlclose).
  /// Defined ONCE in src/core/iora_core.cpp
  /// (PAT-3), NOT as a header inline variable: iora.hpp is compiled into the host
  /// AND into plugin .so's (loaded RTLD_LOCAL), and an inline variable does not
  /// guarantee a single TLS instance across a dlopen boundary. Mirrors
  /// Logger::handlerReentryDepth().
  static bool &ownsLoadModulesMutex();

private:
  /// \brief Erase-remove expired weak_ptrs from a registry bucket. Caller holds
  /// _apiCallGuard.
  static void eraseExpired(std::vector<std::weak_ptr<ISafeApiClearable>> &vec)
  {
    vec.erase(std::remove_if(vec.begin(), vec.end(),
                             [](const std::weak_ptr<ISafeApiClearable> &e) { return e.expired(); }),
              vec.end());
  }

  /// \brief Register a live SafeApiFunction wrapper for clear-before-dlclose.
  /// Guarded by the LEAF _apiCallGuard (safe from onLoad). Prunes expired
  /// entries first.
  void registerSafeApi(const std::string &moduleName, std::weak_ptr<ISafeApiClearable> w)
  {
    std::lock_guard<std::mutex> lock(_apiCallGuard);
    auto &vec = _safeApiRegistry[moduleName];
    eraseExpired(vec);
    vec.push_back(std::move(w));
  }

  /// \brief Snapshot the module's live wrappers (locked shared_ptrs), copy-then-
  /// use so the clear runs outside _apiCallGuard. Guarded by the leaf _apiCallGuard.
  std::vector<std::shared_ptr<ISafeApiClearable>> snapshotSafeApis(const std::string &moduleName)
  {
    std::vector<std::shared_ptr<ISafeApiClearable>> live;
    std::lock_guard<std::mutex> lock(_apiCallGuard);
    auto it = _safeApiRegistry.find(moduleName);
    if (it != _safeApiRegistry.end())
    {
      for (auto &w : it->second)
      {
        if (auto sp = w.lock())
        {
          live.push_back(std::move(sp));
        }
      }
    }
    return live;
  }

  /// \brief Clear every registered wrapper's cache for the module, freeing the
  /// plugin std::function before dlclose. MUST be called with _loadModulesMutex
  /// RELEASED (each invalidateAndClearCache takes a wrapper's cacheMutex, and
  /// operator()'s slow path takes cacheMutex -> _loadModulesMutex; clearing while
  /// holding _loadModulesMutex would close a lock-order cycle). cacheMutex also
  /// makes each clear wait out that wrapper's in-flight invoke.
  void clearSafeApiCaches(const std::string &moduleName)
  {
    for (auto &sp : snapshotSafeApis(moduleName))
    {
      sp->invalidateAndClearCache();
    }
  }

  /// \brief Prune expired wrapper weak_ptrs for the module (and drop the map entry
  /// if empty), so the registry does not grow unboundedly for uniquely-named
  /// modules that are never reloaded. Live wrappers stay registered (they must be
  /// re-cleared on a later unload). Guarded by the leaf _apiCallGuard.
  void pruneSafeApiRegistry(const std::string &moduleName)
  {
    std::lock_guard<std::mutex> lock(_apiCallGuard);
    auto it = _safeApiRegistry.find(moduleName);
    if (it == _safeApiRegistry.end())
    {
      return;
    }
    auto &vec = it->second;
    eraseExpired(vec);
    if (vec.empty())
    {
      _safeApiRegistry.erase(it);
    }
  }

  /// \brief Run ALL host-side teardown for a claimed module — optional dependent
  /// notification, onUnload, unexport its APIs, unregister its ServiceRegistry
  /// entries, erase it from _loadedModules, clean dependency tracking, prune its
  /// registry — but NOT dlclose. Returns true if the module was erased (so the
  /// caller should dlclose it). PRE: holds _loadModulesMutex.
  ///
  /// The dlclose is deferred to the caller so that, for a BATCH unload, EVERY
  /// module's host-side teardown (esp. onUnload, which may touch a sibling) runs
  /// BEFORE ANY dlclose — never onUnload-after-a-sibling's-dlclose. All host-side
  /// destroys (std::function targets in _apiExports, ServiceRegistry objects, the
  /// Plugin instance) run while the .so is still mapped.
  bool teardownModuleHostSideLocked(const std::string &name, bool notifyDependents)
  {
    bool erased = false;
    try
    {
      if (notifyDependents)
      {
        notifyDependentsOfUnload(name);
      }
      auto it = _loadedModules.find(name);
      if (it != _loadedModules.end())
      {
        if (it->second)
        {
          it->second->onUnload();
          for (auto &apiName : it->second->_apiExports)
          {
            // Best-effort: a not-found name (unexportApi throws) must not skip the
            // remaining names / unregister / erase before dlclose.
            try
            {
              unexportApi(apiName);
            }
            catch (const std::exception &)
            {
            }
          }
        }
        // MUST run before erase (invalidates it) and before dlclose (which unmaps
        // the plugin's vtables). unregisterModule never throws.
        ServiceRegistry::unregisterModule(name);
        _loadedModules.erase(it); // unique_ptr will delete
        erased = true;
      }
    }
    catch (const std::exception &e)
    {
      IORA_LOG_ERROR("Failed to unload plugin: " + name + " - " + e.what());
    }
    // Dependency-tracking + registry cleanup regardless of teardown outcome. We do
    // NOT erase _dependents[name]: other plugins still depend on it across a reload.
    _pendingDependencies.erase(name);
    for (auto &dependentList : _dependents)
    {
      auto &dependents = dependentList.second;
      dependents.erase(std::remove(dependents.begin(), dependents.end(), name), dependents.end());
    }
    pruneSafeApiRegistry(name);
    return erased;
  }

  /// \brief Release the unloading claim. PRE: holds _loadModulesMutex.
  void openGate(const std::string &moduleName) { _apiUnloadingModules.erase(moduleName); }

  /// \brief True if the module is currently claimed unloading. PRE: holds
  /// _loadModulesMutex.
  bool isModuleUnloadingLocked(const std::string &moduleName) const
  {
    return _apiUnloadingModules.find(moduleName) != _apiUnloadingModules.end();
  }

  /// \brief RAII guard over a unique_lock<_loadModulesMutex> that keeps
  /// ownsLoadModulesMutex() in sync with the lock's ACTUAL held/released state
  /// across the release/re-acquire window (DP-D), restoring false on every
  /// throw/return path (DP-F). Use its lock()/unlock(); never touch the
  /// underlying lock directly. (_loadModulesMutex is non-recursive, so a single
  /// thread never nests two of these — the bool cannot be clobbered.)
  class LoadModulesGuard
  {
  public:
    explicit LoadModulesGuard(std::mutex &m) : _lk(m) { ownsLoadModulesMutex() = true; }
    ~LoadModulesGuard() { ownsLoadModulesMutex() = false; }
    void unlock()
    {
      ownsLoadModulesMutex() = false;
      _lk.unlock();
    }
    void lock()
    {
      _lk.lock();
      ownsLoadModulesMutex() = true;
    }
    bool ownsLock() const { return _lk.owns_lock(); }

  private:
    std::unique_lock<std::mutex> _lk;
  };

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
  // Guard against dereference when features.server=false.
  // Destructor and other shutdown paths already handle null _webhookServer
  // via `if (_webhookServer)` checks; this accessor is the only public entry
  // point that unconditionally dereferences, so we fail loudly here.
  if (!_webhookServer)
  {
    throw std::logic_error(
      "IoraService::on() called but WebhookServer is disabled "
      "(features.server=false). Enable the server or remove the route "
      "registration.");
  }
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
template <typename R, typename... Args>
class IoraService::SafeApiFunction<R(Args...)> : public ISafeApiClearable
{
private:
  friend class IoraService; // getExportedApiSafe is the sole factory (DP-G).

  // Cached plugin std::function. Its type-erased manager lives in the plugin .so
  // text, so it MUST be cleared (destroyed) before dlclose — done by
  // invalidateAndClearCache() on unload while the .so is still mapped.
  mutable std::function<R(Args...)> cachedFunc;
  mutable std::atomic<bool> valid{false};
  mutable std::mutex cacheMutex; // Protects cachedFunc; also held during invoke
  std::string apiName;
  std::string moduleName;
  IoraService *service;
  mutable std::atomic<bool> eventHandlerRegistered{false};
  mutable std::weak_ptr<SafeApiFunction<R(Args...)>> selfReference;

  /// \brief Resolve the module name for an API. Only ever reached from the ctor
  /// via getExportedApiSafe (the sole factory), which rejects the call when this
  /// thread already holds _loadModulesMutex (host-only, see getExportedApiSafe),
  /// so this always takes the lock — no re-lock of the non-recursive mutex occurs.
  std::string findModuleNameForApi(const std::string &apiName) const
  {
    std::lock_guard<std::mutex> lock(service->_loadModulesMutex);
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

  /// \brief Register event handler safely using weak_ptr.
  /// NOTE: This async module.(unload|reload) -> valid=false invalidation is now
  /// REDUNDANT for safety — the synchronous clear-before-dlclose (invalidateAndClearCache
  /// under the unloading claim) already invalidates the cache before dlclose. It is
  /// retained as harmless belt-and-suspenders (races nothing; valid is atomic); do
  /// NOT reintroduce reliance on the post-dlclose async event for invalidation.
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

  // Private: constructed ONLY by getExportedApiSafe (DP-G), which registers the
  // wrapper intrinsically so no unregistered instance (whose cache would be
  // uncleared before dlclose -> destructor UAF) can exist.
  SafeApiFunction(const std::string &name, IoraService *svc) : apiName(name), service(svc)
  {
    // Resolve the module name up front so registerEventHandler's regex and the
    // registry key are available before first use (DP-F).
    moduleName = findModuleNameForApi(name);
  }

  /// \brief Set the self-reference weak_ptr (called by getExportedApiSafe).
  void setSelfReference(std::weak_ptr<SafeApiFunction<R(Args...)>> ref) { selfReference = ref; }

public:
  /// \brief Invalidate the wrapper and destroy its cached plugin std::function.
  /// Called by the unloader (with _loadModulesMutex released) BEFORE dlclose, so
  /// the plugin-text manager is destroyed while the .so is still mapped. Takes
  /// cacheMutex, which — because operator() invokes UNDER cacheMutex — also waits
  /// out any in-flight invoke of this wrapper before the cache is cleared.
  void invalidateAndClearCache() noexcept override
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    valid.store(false);
    cachedFunc = nullptr;
  }

  /// \brief Function call operator - validates module and calls API (thread-safe).
  /// The invoke runs UNDER cacheMutex; the unloader's invalidateAndClearCache
  /// (also under cacheMutex, with _loadModulesMutex released) therefore serializes
  /// against an in-flight invoke and clears the cache before dlclose — no
  /// per-call drain/counter is needed.
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

    // Module was unloaded/reloaded/unloading, or this is the first call
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
