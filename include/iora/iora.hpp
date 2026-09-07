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
#include <condition_variable>
#include <iostream>
#include <optional>
#include <set>
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

      // Clear all API exports to ensure clean state. Unsynchronized (no
      // _apiMutex hold) is safe ONLY under the documented destroyInstance
      // quiescence precondition — no thread may call getExportedApiSafe or
      // (un)loadModule concurrently with service destruction (see the
      // _safeApiRegistry SHUTDOWN PRECONDITION note near its declaration).
      svc._apiExports.clear();
      svc._apiToModule.clear();

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
  /// This version maintains plugin association for automatic cleanup: the
  /// export is torn down authoritatively via _apiToModule (A-C3) when the
  /// owning plugin's module unloads, so no separate per-plugin bookkeeping
  /// is needed here.
  template <typename Func> void exportApi(Plugin &plugin, const std::string &name, Func &&func)
  {
    exportApi(plugin.getIdentity(), name, std::forward<Func>(func));
  }

  /// \brief Registers an API function with explicit plugin identity (reduces coupling).
  /// Note: An export whose pluginIdentity matches a loaded module's name is
  /// AUTO-UNEXPORTED when that module unloads (see removeExportsForModule),
  /// via the _apiToModule reverse map populated below. There is no per-name
  /// manual unexport API: an export whose pluginIdentity does not correspond
  /// to a module name known to _loadedModules (e.g. a synthetic/host-owned
  /// identity) is cleared only at service shutdown, alongside every other
  /// export.
  template <typename Func>
  void exportApi(const std::string &pluginIdentity, const std::string &name, Func &&func)
  {
    if (name.empty())
    {
      core::Logger::error("IoraService::exportApi() - Plugin API name cannot be empty");
      throw std::invalid_argument("Plugin API name cannot be empty");
    }
    // Check-then-insert must be atomic under _apiMutex: reading _apiExports
    // outside the lock is a data race with concurrent exportApi calls and a
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
    // Single write site (A-C1): this is the ONLY place _apiToModule is
    // populated. The exportApi(Plugin&, ...) overload gets this for free via
    // its delegation to this overload and must NOT write _apiToModule itself
    // (a second, unguarded write there would be a data race with this
    // _apiMutex-guarded one).
    _apiToModule[name] = pluginIdentity;
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
  /// Throws std::runtime_error if the API is not found, the owning module is not
  /// loaded / is unloading, or the signature does not match.
  ///
  /// The exported callable is copied out of _apiExports and invoked+destroyed on
  /// the caller stack outside any lock, but the copy is protected against a
  /// concurrent module unload by the per-module in-flight drain gate: the owning
  /// module is resolved, entered (rejected if an unload is draining it), and the
  /// unload path WAITS for this call to complete before it tears the module down
  /// (DP-1b). \note The return type MUST be HOST-OWNED. C++17 guaranteed copy
  /// elision materializes the returned object in the CALLER's frame, so a return
  /// type whose destructor lives in the plugin .so would run AFTER the drain
  /// releases — outside the gate's protection. All in-repo callers return host-
  /// owned types (iora_media codecs return CodecRegistry& / a reference; karoo_tmc
  /// returns Json). The copied std::function itself IS protected (it is destroyed
  /// before leaveApiCall by the declaration order below).
  template <typename Ret, typename... Args>
  Ret callExportedApi(const std::string &name, Args &&...args)
  {
    core::Logger::debug("IoraService::callExportedApi() - Calling plugin API: " + name);

    // (1) Resolve the owning module authoritatively (Slice A reverse map).
    std::string module;
    {
      std::lock_guard<std::mutex> lock(_apiMutex);
      auto owner = resolveOwningModuleLocked(name);
      if (!owner)
      {
        throw std::runtime_error("API not found: " + name);
      }
      module = *owner;
    }

    // (1b) Is-loaded gate (DP-6b): reject a call to a not-yet-loaded (mid-onLoad)
    // or mid-unload-claim module, mirroring SafeApiFunction::operator(). This
    // _loadModulesMutex acquisition is taken-and-released here, NEVER nested with
    // _apiMutex or _apiCallGuard, so no lock-order edge is introduced.
    if (!isModuleLoaded(module))
    {
      throw std::runtime_error("plugin API unavailable: module " + module + " not loaded");
    }

    // (2) Enter the drain gate. A rejected call never materializes a copy.
    if (!enterApiCall(module))
    {
      throw std::runtime_error("plugin API unavailable: module " + module + " is unloading");
    }

    // (3)+(4) Arm the leave-guard IMMEDIATELY (M-A: before the thread-local push,
    // so a throwing push still runs leaveApiCall — no permanent drain hang), then
    // push. The guard pops ONE entry (erase(find), NOT erase(key) which would
    // drop all equal entries and corrupt the reentrant/transitive count — M1) and
    // calls leaveApiCall. Declared BEFORE `func` so ~func (the .so-resident
    // manager) runs before leaveApiCall (DP-8 belt-and-suspenders).
    struct LeaveGuard
    {
      IoraService *svc;
      const std::string *module;
      bool pushed = false;
      ~LeaveGuard() noexcept
      {
        try
        {
          if (pushed)
          {
            auto &set = IoraService::inFlightApiModules();
            auto it = set.find(*module);
            if (it != set.end())
            {
              set.erase(it); // erase ONE (M1)
            }
          }
          svc->leaveApiCall(*module);
        }
        catch (...)
        {
          // leaveApiCall locks _apiCallGuard; std::mutex::lock can throw. This
          // dtor is noexcept, so a propagating throw would std::terminate — a
          // _apiCallGuard lock failure is treated as unrecoverable but is
          // swallowed here rather than crash the process (L-4).
        }
      }
    } guard{this, &module};
    IoraService::inFlightApiModules().insert(module);
    guard.pushed = true;

    // (5) Copy WITH an owner re-check in the SAME _apiMutex hold (C-1): between
    // resolving M and copying, a concurrent unexport+re-export could rebind the
    // name to a DIFFERENT module P while our gate protects M. Re-resolving
    // owner==M under the copy hold proves the copied function belongs to the
    // drained module M. `func` is declared here (after the guard) for the DP-8
    // destruction ordering.
    std::function<Ret(Args...)> func;
    {
      std::lock_guard<std::mutex> lock(_apiMutex);
      auto owner = resolveOwningModuleLocked(name);
      auto it = _apiExports.find(name);
      if (!owner || *owner != module || it == _apiExports.end())
      {
        throw std::runtime_error("API not found or owner changed for: " + name);
      }
      func = it->second.get<Ret(Args...)>(name);
    }

    // (6) Invoke off all locks. The gate keeps M's host-side teardown waiting
    // until this returns and the guard fires leaveApiCall.
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

    // Self-unload guard (DP-7 / H-C): if this thread is inside a callExportedApi
    // of this module, draining it would wait on an in-flight count that includes
    // this thread — a deadlock. Detect and throw BEFORE claiming, so no claim is
    // leaked (a throw after the claim would brick the module as "unloading").
    if (inFlightApiModules().count(pluginName) > 0)
    {
      throw std::runtime_error("cannot unload module " + pluginName +
                               " from within its own exported API call (self-unload deadlock)");
    }

    // Claim the module: new operator() calls now observe it as "not loaded" and
    // throw, and a concurrent same-name load/unload fails fast. beginApiDrain in
    // the SAME critical section marks the callExportedApi gate draining so no new
    // call slips past the claim-to-drain gap.
    _apiUnloadingModules.insert(pluginName);
    beginApiDrain(pluginName);

    // Clear every registered wrapper's cache AND drain in-flight callExportedApi
    // copies with _loadModulesMutex RELEASED. clearSafeApiCaches takes each
    // wrapper's cacheMutex (serializes against operator()); drainApiCalls waits
    // out in-flight callExportedApi invokes of this module. Both run off
    // _loadModulesMutex (DP-3: an in-flight call must be able to complete) and
    // COMPLETE before teardownModuleHostSideLocked destroys the plugin object
    // (DP-1b). Restore the claim AND the gate on any throw (snapshotSafeApis /
    // CV wait / guard.lock() can throw) so a failure does not brick the module.
    try
    {
      guard.unlock();
      clearSafeApiCaches(pluginName);
      drainApiCalls(pluginName);
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
    // did). The claim + gate are released regardless: a throw from
    // PluginManager::unloadPlugin (its mutex lock / a dtor) must NOT skip openGate,
    // else the claim AND draining=true leak and the module name is permanently
    // bricked for callExportedApi/isModuleLoaded (TS-2).
    bool ok = false;
    try
    {
      ok = teardownModuleHostSideLocked(pluginName, /*notifyDependents=*/true);
      if (ok)
      {
        PluginManager::unloadPlugin(pluginName); // dlclose AFTER host-side teardown
      }
    }
    catch (...)
    {
      openGate(pluginName);
      throw;
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
      // Self-unload skip (DP-7 / H-C): if this thread is inside a callExportedApi
      // of this module, draining it would deadlock on our own in-flight count.
      // SKIP it (do not claim, do not tear down) and report failure — rather than
      // throw and abort the unrelated modules of a shutdown batch. Checked BEFORE
      // the claim so no claim is leaked.
      if (inFlightApiModules().count(name) > 0)
      {
        IORA_LOG_ERROR("Skipping unload of module " + name +
                       " during unloadAllModules: it has an in-flight exported API call on this "
                       "thread (self-unload deadlock).");
        success = false;
        continue;
      }
      _apiUnloadingModules.insert(name);
      beginApiDrain(name);
      names.push_back(name);
    }

    // Clear all wrapper caches AND drain in-flight callExportedApi copies with
    // _loadModulesMutex RELEASED (see unloadSingleModule): each clear serializes
    // against in-flight invokes via cacheMutex; each drain waits out in-flight
    // callExportedApi invokes of that module — both COMPLETE before the teardown
    // pass destroys any plugin object (DP-1b). Restore all claims AND gates on
    // any throw so a failure does not brick modules as "unloading".
    try
    {
      guard.unlock();
      for (const auto &name : names)
      {
        clearSafeApiCaches(name);
        drainApiCalls(name);
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
    // The claim + gate for EVERY claimed name are released regardless of a
    // teardown/dlclose throw (TS-2): a throw here must not skip the openGate loop,
    // else the surviving names leak their claim + draining=true and are bricked.
    try
    {
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
    }
    catch (...)
    {
      for (const auto &name : names)
      {
        openGate(name);
      }
      throw;
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
          catch (const std::exception &)
          {
            // onLoad (or the subsequent insert/notify) failed AFTER the plugin may
            // have exported APIs / registered ServiceRegistry entries. Those hold
            // plugin-resident std::functions / objects; tear them down HOST-SIDE now
            // — while the plugin object and its .so are still mapped — BEFORE the
            // outer catch dlcloses. Otherwise they dangle into the unmapped .so and
            // fault at the next call or at ~IoraService (_apiExports.clear()). (C1)
            //
            // Authoritative teardown (A-C3, cpp17 H-1): resolve the exported
            // names to remove from _apiToModule, keyed by pluginName, rather
            // than from the (possibly moved-from / not-yet-captured)
            // pluginInstance object. This covers BOTH the onLoad-throw
            // sub-case (pluginInstance still owned, never inserted) and the
            // insert/notify-throw sub-case (pluginInstance moved into
            // _loadedModules) uniformly, and also covers identity-overload
            // exports the old Plugin::_apiExports-based iteration never saw.
            removeExportsForModule(pluginName);
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

  /// \brief Resolve the module that owns an exported API from the
  /// authoritative reverse map. PRECONDITION: caller holds _apiMutex (this
  /// helper does not lock, so it can be reused by callers that must take
  /// _apiMutex themselves to avoid a double-lock, e.g. findModuleNameForApi).
  /// \return the owning module name, or std::nullopt if the API is not
  /// (or no longer) exported.
  std::optional<std::string> resolveOwningModuleLocked(const std::string &apiName) const
  {
    auto it = _apiToModule.find(apiName);
    if (it == _apiToModule.end())
    {
      return std::nullopt;
    }
    return it->second;
  }

  /// \brief Authoritative teardown: remove every API exported by `module`
  /// from BOTH _apiExports and _apiToModule in a single _apiMutex hold
  /// (A-DP-4). Owner-checked (only entries whose recorded module == `module`
  /// are erased, so a name re-bound to a different live module survives) and
  /// leak-free (no snapshot-then-release gap between resolving and erasing).
  /// Replaces the old snapshot-then-loop per-name teardown, which raced
  /// concurrent exportApi calls (neither was gated by the unloading claim)
  /// and could wrong-unexport a re-bound name or leak a post-snapshot export.
  /// This ACQUIRES _apiMutex itself (hence no "...Locked" suffix): the
  /// caller MUST NOT already hold _apiMutex (that would self-deadlock the
  /// non-recursive mutex).
  /// PRECONDITION: caller holds _loadModulesMutex (the existing
  /// _loadModulesMutex -> _apiMutex lock order).
  void removeExportsForModule(const std::string &module)
  {
    std::lock_guard<std::mutex> lock(_apiMutex);
    for (auto it = _apiToModule.begin(); it != _apiToModule.end();)
    {
      if (it->second == module)
      {
        _apiExports.erase(it->first);
        it = _apiToModule.erase(it);
      }
      else
      {
        ++it;
      }
    }
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
  // Authoritative apiName -> owning-module-name reverse map (tracker
  // 2026-09-07-8, architecture/iora/api_module_reverse_map.json, A-DP-1).
  // Guarded by _apiMutex and mutated in the SAME critical sections as
  // _apiExports, so the two maps never disagree. Populated ONLY by the
  // identity-overload exportApi(pluginIdentity, name, func); erased by
  // removeExportsForModule; cleared together with _apiExports at shutdown.
  std::unordered_map<std::string, std::string> _apiToModule;
  // Lock order: _loadModulesMutex (outer) -> _apiMutex (inner). Any code
  // path that must hold both acquires _loadModulesMutex first. _apiCallGuard
  // (declared below) is a leaf guarding TWO unrelated concerns: the
  // SafeApiFunction registry AND the callExportedApi drain gate (Slice B). It is
  // taken alone by the gate accessors and the registry accessors; the unload
  // paths hold _loadModulesMutex and then take _apiCallGuard (beginApiDrain /
  // endApiDrain via openGate, and teardown -> pruneSafeApiRegistry) — the
  // _loadModulesMutex -> _apiCallGuard edge is ACYCLIC and pre-existing; NO path
  // takes _loadModulesMutex while holding _apiCallGuard, and callExportedApi
  // enters/leaves the gate DISJOINT from its _apiMutex copy (never both held).
  // (The load-failure drain adds another _loadModulesMutex -> _apiCallGuard site
  // in Slice C, tracker 2026-09-07-9 — same acyclic direction.)
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
  // leaf guarding the registry (snapshot + registration) AND the callExportedApi
  // drain gate (_apiCallGates + _apiDrainCv, Slice B) — see the lock-order note
  // above.
  mutable std::mutex _apiCallGuard;
  // Modules currently unloading (claim). Guarded by _loadModulesMutex. Gates ALL
  // same-name module-map mutations: operator()/isModuleLoadedLocked report NOT
  // loaded, load/reload fail-fast, a second unload no-ops.
  std::unordered_set<std::string> _apiUnloadingModules;
  // Live SafeApiFunction wrappers per module, for clear-before-dlclose. Guarded by
  // the LEAF _apiCallGuard so registration is safe from a plugin onLoad (which
  // holds _loadModulesMutex). SHUTDOWN PRECONDITION: this map is destroyed with the
  // IoraService (destroyInstance) off _apiCallGuard, so — like the rest of the
  // service — no thread may call getExportedApiSafe, callExportedApi, or
  // (un)loadModule concurrently with service destruction (the documented
  // destroyInstance() precondition). callExportedApi touches _apiMutex,
  // _apiCallGuard, _apiExports, _apiCallGates and _apiDrainCv, all destroyed in
  // ~IoraService, so a call racing destruction is the same UB class (TS-3).
  std::unordered_map<std::string, std::vector<std::weak_ptr<ISafeApiClearable>>> _safeApiRegistry;

  // --- callExportedApi in-flight drain gate (Slice B, tracker 2026-09-07-3,
  // architecture/iora/callexportedapi_gating.json). Closes the use-after-free
  // in callExportedApi: it copies a plugin std::function out of _apiExports
  // under _apiMutex, releases the lock, then invokes+destroys the copy with NO
  // lock held. The copy captures the plugin OBJECT (e.g. a codec module's
  // [this]{return *_registry;}); a concurrent unload's host-side teardown
  // (onUnload + ~Plugin) + dlclose in that window makes the copy dereference
  // destroyed state. The gate makes an unload WAIT for in-flight calls to a
  // module before that module's host-side teardown (DP-1b: drain-before-
  // teardown, not merely before dlclose).
  //
  // Per-module {inFlight count, draining flag} + a shared CV, guarded by the
  // EXISTING leaf _apiCallGuard (which also guards _safeApiRegistry above — the
  // two are unrelated concerns co-located under one leaf, justified on lock-
  // order grounds: see the lock-order comment above and DP-5/DP-11).
  struct ApiCallGate
  {
    std::size_t inFlight = 0;
    bool draining = false;
  };
  std::unordered_map<std::string, ApiCallGate> _apiCallGates;
  std::condition_variable _apiDrainCv;

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

  /// \brief Thread-local MULTISET of module names with a callExportedApi call
  /// currently in-flight on THIS thread (pushed at the drain-gate enter, popped
  /// at leave). Consulted by the unload paths BEFORE they claim+drain a module:
  /// if the module a thread is trying to unload is in this set, the unload would
  /// wait on an in-flight count that includes the calling thread itself — a
  /// self-unload deadlock — so the unloader throws/skips instead (DP-7). A
  /// MULTISET (not a counter, not a single marker) so the transitive chain
  /// callExportedApi(M.f) -> f calls callExportedApi(N.g) -> g unloads M holds
  /// BOTH M and N, and a reentrant call of the SAME module nests correctly.
  ///
  /// Defined ONCE in src/core/iora_core.cpp (PAT-3), NOT as a header inline
  /// thread_local: callExportedApi is a template instantiated into the host AND
  /// into plugin .so's (loaded RTLD_LOCAL), and an inline thread_local does not
  /// guarantee a single TLS instance across a dlopen boundary — the plugin-TU
  /// push and the host-TU unload check would touch DIFFERENT sets and the guard
  /// would silently fail. Mirrors ownsLoadModulesMutex() /
  /// Logger::handlerReentryDepth().
  static std::multiset<std::string> &inFlightApiModules();

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

  // --- callExportedApi drain-gate methods (Slice B). All take the LEAF
  // _apiCallGuard; none nests another lock under it. callExportedApi enters and
  // leaves the gate DISJOINT from its _apiMutex copy (never both held). The
  // unload paths call begin/end/drain while holding _loadModulesMutex (the
  // acyclic _loadModulesMutex -> _apiCallGuard edge — same as
  // teardownModuleHostSideLocked -> pruneSafeApiRegistry).

  /// \brief Mark a callExportedApi call in-flight for a module. Returns false if
  /// the module is draining (an unload has claimed it) — the caller then rejects
  /// without taking a copy. operator[] is intended: enterApiCall is the gate's
  /// creator. Guarded by the leaf _apiCallGuard.
  bool enterApiCall(const std::string &moduleName)
  {
    std::lock_guard<std::mutex> lock(_apiCallGuard);
    auto &g = _apiCallGates[moduleName];
    if (g.draining)
    {
      return false;
    }
    ++g.inFlight;
    return true;
  }

  /// \brief Mark an in-flight callExportedApi call complete. MUST use find() +
  /// assert, NEVER operator[]: an absent entry followed by --inFlight would wrap
  /// std::size_t to SIZE_MAX and hang the next drain forever (H-2). Notifies the
  /// drain CV UNDER _apiCallGuard at the last in-flight departure — the woken
  /// waiter proceeds to host-side teardown/dlclose (the destroyer shape), so
  /// notify-under-lock is the correct discipline here (see
  /// reference_cv_notify_under_lock_when_destroyer_observes). Also erases an idle
  /// non-draining gate so the map does not accumulate {inFlight:0} entries for
  /// the owner-swap orphan case or for unboundedly-many distinct module names.
  void leaveApiCall(const std::string &moduleName)
  {
    std::lock_guard<std::mutex> lock(_apiCallGuard);
    auto it = _apiCallGates.find(moduleName);
    assert(it != _apiCallGates.end() && it->second.inFlight > 0 &&
           "leaveApiCall without a matching enterApiCall");
    if (it == _apiCallGates.end() || it->second.inFlight == 0)
    {
      return; // defensive: never underflow
    }
    if (--it->second.inFlight == 0)
    {
      if (it->second.draining)
      {
        _apiDrainCv.notify_all();
      }
      else
      {
        // No unload waiting on this gate — drop it so the map stays bounded.
        _apiCallGates.erase(it);
      }
    }
  }

  /// \brief Begin draining a module: new enterApiCall for it is rejected. Set in
  /// the SAME _loadModulesMutex critical section as the unload claim, so no new
  /// call slips past the claim-to-drain gap. Guarded by the leaf _apiCallGuard.
  void beginApiDrain(const std::string &moduleName)
  {
    std::lock_guard<std::mutex> lock(_apiCallGuard);
    _apiCallGates[moduleName].draining = true;
  }

  /// \brief Block until no callExportedApi call to the module is in-flight. MUST
  /// run with _loadModulesMutex RELEASED (DP-3): an in-flight call must be able
  /// to complete (its copy+invoke never holds _loadModulesMutex), so waiting
  /// under _loadModulesMutex could not make progress. The predicate is
  /// gate-absent OR inFlight==0 (loop-safe against spurious wakeups).
  ///
  /// KNOWN LIMITATION (TS-1, unsupported topology): the thread-local in-flight set
  /// (inFlightApiModules) breaks the SAME-thread self/transitive unload cycle
  /// (DP-7) but NOT a cross-thread MUTUAL one — thread A, inside a callExportedApi
  /// of module M, unloading N while thread B, inside a callExportedApi of N,
  /// unloads M: A's drain of N waits for B's in-flight N, B's drain of M waits for
  /// A's in-flight M -> a condition-variable wait-cycle (no lock is held across the
  /// wait, so it is not a lock deadlock and TSan cannot see it). Unloading a module
  /// from within an exported API call of a DIFFERENT still-in-flight module on
  /// another thread is unsupported (no in-repo caller does this). Documented per a
  /// human decision (2026-09-07) to not bound the wait (a bounded timeout would
  /// spuriously abort legitimately-long in-flight calls the drain must wait for).
  void drainApiCalls(const std::string &moduleName)
  {
    std::unique_lock<std::mutex> lock(_apiCallGuard);
    _apiDrainCv.wait(lock,
                     [&]
                     {
                       auto it = _apiCallGates.find(moduleName);
                       return it == _apiCallGates.end() || it->second.inFlight == 0;
                     });
  }

  /// \brief End draining a module and drop its gate once idle. Clears draining,
  /// then erases the gate iff inFlight==0 (the exact erase precondition:
  /// inFlight==0 && !draining after the clear). Guarded by the leaf
  /// _apiCallGuard.
  void endApiDrain(const std::string &moduleName)
  {
    std::lock_guard<std::mutex> lock(_apiCallGuard);
    auto it = _apiCallGates.find(moduleName);
    if (it != _apiCallGates.end())
    {
      it->second.draining = false;
      if (it->second.inFlight == 0)
      {
        _apiCallGates.erase(it);
      }
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
        }
        // Authoritative teardown (A-C3): a single owner-checked atomic erase
        // over _apiToModule, covering BOTH the exportApi(Plugin&) and
        // exportApi(pluginIdentity, ...) overloads from one source of truth
        // (replaces the old Plugin::_apiExports iteration, which never saw
        // identity-overload exports).
        removeExportsForModule(name);
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

  /// \brief Release the unloading claim AND end the callExportedApi drain for the
  /// module (clears draining + drops the idle gate). Paired with the
  /// beginApiDrain set at claim time, on BOTH the success path (after dlclose)
  /// and the throw-restore path — so a failure never leaves a gate stuck
  /// draining=true (which would reject every future call to the name). PRE: holds
  /// _loadModulesMutex.
  void openGate(const std::string &moduleName)
  {
    _apiUnloadingModules.erase(moduleName);
    endApiDrain(moduleName);
  }

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

  /// \brief Resolve the module name for an API from the authoritative
  /// _apiToModule reverse map (A-DP-2 / A-C2). Only ever reached from the
  /// ctor via getExportedApiSafe (the sole factory), which rejects the call
  /// when this thread already holds _loadModulesMutex (host-only, see
  /// getExportedApiSafe) — so no SafeApiFunction is ever constructed while
  /// _apiMutex is held (A-DP-5 reentrancy invariant), and this can safely
  /// take _apiMutex itself. NOT-FOUND: throws (A-DP-2) rather than guessing a
  /// "<prefix>.so" module name and handing back a wrapper for an API that was
  /// never (or is no longer) exported — deferred/pre-export binding is
  /// intentionally not supported.
  std::string findModuleNameForApi(const std::string &apiName) const
  {
    std::lock_guard<std::mutex> lock(service->_apiMutex);
    auto module = service->resolveOwningModuleLocked(apiName);
    if (!module.has_value())
    {
      throw std::runtime_error("API not found: " + apiName);
    }
    return *module;
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
