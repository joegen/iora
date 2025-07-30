#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include <subprocess.hpp>
#include <toml++/toml.h>
#include <nlohmann/json.hpp>
#include <httplib.h>
#include <mutex>
#include <unordered_map>
#include <optional>
#include <chrono>
#include <sstream>
#include <algorithm>
#include <cpr/cpr.h>
#include <stdexcept>
#include <filesystem>

#ifdef iora_USE_TIKTOKEN
#include <tiktoken/encodings.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace iora
{
/// JSON type alias to avoid exposing third-party namespaces.
namespace json
{
  using Json = nlohmann::json;
} // namespace json

namespace config
{
  /// \brief Loads and parses TOML configuration files for the application.
  class ConfigLoader
  {
  public:
    /// \brief Constructs and loads a TOML configuration file.
    explicit ConfigLoader(const std::string& filename) : _filename(filename)
    {
    }

    /// \brief Reloads the configuration from disk.
    bool reload()
    {
      try
      {
        _table = toml::parse_file(_filename);
        return true;
      }
      catch (...)
      {
        _table = toml::table{};
        return false;
      }
    }

    const toml::table& load()
    {
      if (_table.empty())
      {
        if (!reload())
        {
          throw std::runtime_error("Failed to load configuration file: " + _filename);
        }
      }
      return _table;
    }

    /// \brief Gets the full configuration table.
    const toml::table& table() const { return _table; }

    /// \brief Gets a typed value from the configuration.
    /// \tparam T Must be a TOML native type (int64_t, double, bool, std::string, etc.)
    template <typename T>
    std::optional<T> get(const std::string& dottedKey) const
    {
      auto node = _table.at_path(dottedKey);
      if (node && node.is_value())
      {
        if (auto val = node.as<T>())
        {
          return val->get();
        }
      }
      return std::nullopt;
    }

    /// \brief Gets an int value from the configuration.
    std::optional<int64_t> getInt(const std::string& key) const
    {
      return get<int64_t>(key);
    }

    /// \brief Gets a bool value from the configuration.
    std::optional<bool> getBool(const std::string& key) const
    {
      return get<bool>(key);
    }

    /// \brief Gets a string value from the configuration.
    std::optional<std::string> getString(const std::string& key) const
    {
      return get<std::string>(key);
    }

  private:
    std::string _filename;
    toml::table _table;
  };

} // namespace config

namespace state
{
  /// \brief In-memory key-value store for string data with basic get/set
  /// operations.
  struct CaseInsensitiveHash
  {
    std::size_t operator()(const std::string& key) const
    {
      std::string lowered = key;
      std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                     ::tolower);
      return std::hash<std::string>{}(lowered);
    }
  };

  struct CaseInsensitiveEqual
  {
    bool operator()(const std::string& lhs, const std::string& rhs) const
    {
      return std::equal(lhs.begin(), lhs.end(), rhs.begin(), rhs.end(),
                        [](char a, char b)
                        { return std::tolower(a) == std::tolower(b); });
    }
  };

  class ConcreteStateStore
  {
  public:
    /// \brief Sets a key-value pair in the store.
    void set(const std::string& key, const std::string& value)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _store[key] = value;
    }

    /// \brief Gets a value by key from the store.
    std::optional<std::string> get(const std::string& key) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _store.find(key);
      if (it != _store.end())
      {
        return it->second;
      }
      return std::nullopt;
    }

    /// \brief Removes a key from the store.
    bool remove(const std::string& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      return _store.erase(key) > 0;
    }

    /// \brief Checks if a key exists in the store.
    bool contains(const std::string& key) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      return _store.find(key) != _store.end();
    }

    /// \brief Returns all keys in the store.
    std::vector<std::string> keys() const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      std::vector<std::string> result;
      result.reserve(_store.size());
      for (const auto& [k, _] : _store)
      {
        result.push_back(k);
      }
      return result;
    }

    /// \brief Returns the number of entries in the store.
    std::size_t size() const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      return _store.size();
    }

    /// \brief Returns true if the store is empty.
    bool empty() const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      return _store.empty();
    }

    /// \brief Finds all keys with the given prefix.
    std::vector<std::string> findKeysWithPrefix(const std::string& prefix) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      std::vector<std::string> result;
      for (const auto& [key, _] : _store)
      {
        if (key.rfind(prefix, 0) == 0) // key starts with prefix
        {
          result.push_back(key);
        }
      }
      return result;
    }

    /// \brief Finds all keys whose values match the provided value.
    std::vector<std::string> findKeysByValue(const std::string& value) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      std::vector<std::string> result;
      for (const auto& [key, val] : _store)
      {
        if (val == value)
        {
          result.push_back(key);
        }
      }
      return result;
    }

    /// \brief Finds all keys satisfying a custom matcher.
    std::vector<std::string>
    findKeysMatching(std::function<bool(const std::string&)> matcher) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      std::vector<std::string> result;
      for (const auto& [key, _] : _store)
      {
        if (matcher(key))
        {
          result.push_back(key);
        }
      }
      return result;
    }

  private:
    mutable std::mutex _mutex;
    std::unordered_map<std::string, std::string, CaseInsensitiveHash,
                       CaseInsensitiveEqual>
        _store;
  };

  /// \brief Thread-safe key-value store backed by a JSON file with background
  /// flushing and persistence.
  class JsonFileStore
  {
  public:
    /// \brief Construct and load JSON file if it exists
    explicit JsonFileStore(std::string filename)
      : _filename(std::move(filename)), _dirty(false)
    {
      std::ifstream file(_filename);
      if (file)
      {
        try
        {
          file >> _store;
        }
        catch (...)
        {
          _store = json::Json::object();
        }
      }
      else
      {
        _store = json::Json::object();
      }

      registerStore();
    }

    /// \brief Destructor unregisters the store
    ~JsonFileStore()
    {
      unregisterStore();
      flush();
    }

    /// \brief Set a key to a value and mark store dirty
    template <typename T> void set(const std::string& key, const T& value)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _store[key] = value;
      _dirty = true;
    }

    /// \brief Specialization for std::string
    void set(const std::string& key, const std::string& value)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _store[key] = value;
      _dirty = true;
    }

    /// \brief Get a value from the store
    template <typename T> std::optional<T> get(const std::string& key) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_store.contains(key))
      {
        try
        {
          return _store[key].get<T>();
        }
        catch (...)
        {
          return std::nullopt;
        }
      }
      return std::nullopt;
    }

    /// \brief Specialization for std::string
    std::optional<std::string> get(const std::string& key) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_store.contains(key))
      {
        try
        {
          return _store[key].get<std::string>();
        }
        catch (...)
        {
          return std::nullopt;
        }
      }
      return std::nullopt;
    }

    /// \brief Remove a key from the store and mark dirty
    void remove(const std::string& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _store.erase(key);
      _dirty = true;
    }

    /// \brief Immediately write the store to disk
    void flush()
    {
      std::lock_guard<std::mutex> lock(_mutex);
      saveToFile();
      _dirty = false;
    }

    /// \brief Configure the background flush interval (in milliseconds)
    static void setFlushInterval(std::chrono::milliseconds interval)
    {
      _flushInterval = interval;
    }

  private:
    void saveToFile() const
    {
      std::ofstream file(_filename);
      if (file)
      {
        file << _store.dump(2);
      }
    }

    void tryFlushIfDirty()
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_dirty)
      {
        saveToFile();
        _dirty = false;
      }
    }

    void registerStore()
    {
      std::lock_guard<std::mutex> lock(_registryMutex);
      _registry.insert(this);
      if (_registry.size() == 1)
      {
        _stopFlushThread = false;
        _flushThread = std::thread(flushThreadFunc);
        _flushThread.detach();
      }
    }

    void unregisterStore()
    {
      std::lock_guard<std::mutex> lock(_registryMutex);
      _registry.erase(this);
      if (_registry.empty())
      {
        _stopFlushThread = true;
      }
    }

    static void flushThreadFunc()
    {
      while (!_stopFlushThread)
      {
        std::this_thread::sleep_for(_flushInterval);

        std::lock_guard<std::mutex> lock(_registryMutex);
        for (auto* store : _registry)
        {
          store->tryFlushIfDirty();
        }
      }
    }

    const std::string _filename;
    mutable std::mutex _mutex;
    json::Json _store;
    bool _dirty;

    static inline std::set<JsonFileStore*> _registry;
    static inline std::mutex _registryMutex;
    static inline std::thread _flushThread;
    static inline std::atomic<bool> _stopFlushThread{false};
    static inline std::chrono::milliseconds _flushInterval{2000};
  };

} // namespace state

namespace util
{
  /// \brief Thread-safe event queue for dispatching JSON events to registered
  /// handlers using worker threads.
  class EventQueue
  {
  public:
    using Handler = std::function<void(const json::Json&)>;

    /// \brief Construct the event queue and spin up worker threads
    EventQueue(std::size_t threadCount = std::thread::hardware_concurrency())
    {
      for (std::size_t i = 0; i < threadCount; ++i)
      {
        _threads.emplace_back([this]() { this->workerLoop(); });
      }
    }

    /// \brief Destructor gracefully shuts down the worker threads
    ~EventQueue()
    {
      {
        std::unique_lock<std::mutex> lock(_mutex);
        _shutdown = true;
      }

      _cv.notify_all();

      for (auto& thread : _threads)
      {
        if (thread.joinable())
        {
          thread.join();
        }
      }
    }

    /// \brief Enqueue an event for processing
    void push(const json::Json& event)
    {
      if (!isValidEvent(event))
      {
        return; // drop invalid event
      }

      {
        std::unique_lock<std::mutex> lock(_mutex);
        _queue.push(event);
      }

      _cv.notify_one();
    }

    /// \brief Register a handler for an exact eventId
    void onEventId(const std::string& eventId, Handler handler)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _handlersById[eventId].emplace_back(std::move(handler));
    }

    /// \brief Register a handler for an exact eventName
    void onEventName(const std::string& eventName, Handler handler)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _handlersByName[eventName].emplace_back(std::move(handler));
    }

    /// \brief Register a handler for an eventName using regex matching
    void onEventNameMatches(const std::string& eventNamePattern,
                            Handler handler)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _compiledHandlersByName[eventNamePattern] =
          std::make_pair(std::regex(eventNamePattern), std::move(handler));
    }

  private:
    bool isValidEvent(const json::Json& event) const
    {
      return event.contains("eventId") && event.contains("eventName");
    }

    std::mutex _mutex;
    std::condition_variable _cv;
    std::queue<json::Json> _queue;
    std::map<std::string, std::vector<Handler>> _handlersById;
    std::map<std::string, std::vector<Handler>> _handlersByName;
    std::map<std::string, std::pair<std::regex, Handler>>
        _compiledHandlersByName;
    std::vector<std::thread> _threads;
    bool _shutdown = false;

    void workerLoop()
    {
      while (true)
      {
        json::Json event;

        {
          std::unique_lock<std::mutex> lock(_mutex);
          _cv.wait(lock, [this]() { return !_queue.empty() || _shutdown; });

          if (_shutdown && _queue.empty())
          {
            return;
          }

          event = _queue.front();
          _queue.pop();
        }

        dispatch(event);
      }
    }

    void dispatch(const json::Json& event)
    {
      const std::string eventId = event["eventId"];
      const std::string eventName = event["eventName"];

      bool handled = false;

      std::vector<Handler> idHandlers;
      std::vector<Handler> nameHandlers;

      {
        std::unique_lock<std::mutex> lock(_mutex);

        auto idHandlersIt = _handlersById.find(eventId);
        if (idHandlersIt != _handlersById.end())
        {
          idHandlers = idHandlersIt->second;
        }

        auto nameHandlersIt = _handlersByName.find(eventName);
        if (nameHandlersIt != _handlersByName.end())
        {
          nameHandlers = nameHandlersIt->second;
        }

        for (const auto& [pattern, compiledHandler] : _compiledHandlersByName)
        {
          if (std::regex_match(eventName, compiledHandler.first))
          {
            nameHandlers.emplace_back(compiledHandler.second);
          }
        }
      }

      for (const auto& handler : idHandlers)
      {
        handler(event);
        handled = true;
      }

      for (const auto& handler : nameHandlers)
      {
        handler(event);
        handled = true;
      }

      if (!handled)
      {
        // silently discard
      }
    }

    bool eventNameMatches(const std::string& pattern,
                          const std::string& name) const
    {
      if (pattern.find('*') == std::string::npos)
      {
        return pattern == name;
      }

      std::string regexPattern;
      regexPattern.reserve(pattern.size() * 2);
      for (char ch : pattern)
      {
        if (ch == '*')
        {
          regexPattern += ".*";
        }
        else if (std::isalnum(static_cast<unsigned char>(ch)) || ch == ':' ||
                 ch == '_')
        {
          regexPattern += ch;
        }
        else
        {
          regexPattern += '\\';
          regexPattern += ch;
        }
      }

      try
      {
        return std::regex_match(name, std::regex(regexPattern));
      }
      catch (...)
      {
        return false;
      }
    }
  };

  // Forward declaration for friend accessor
  template <typename K, typename V> struct ExpiringCacheTestAccessor;
  /// \brief Thread-safe expiring cache with time-to-live (TTL) and automatic
  /// purging of stale entries.
  template <typename K, typename V> class ExpiringCache
  {
  public:
    ExpiringCache() : _ttl(std::chrono::seconds(60)), _stop(false)
    {
      startPurgeThread();
    }

    explicit ExpiringCache(std::chrono::seconds ttl) : _ttl(ttl), _stop(false)
    {
      startPurgeThread();
    }

    ~ExpiringCache()
    {
      {
        std::lock_guard<std::mutex> lock(_mutex);
        _stop = true;
      }
      if (_purgeThread.joinable())
      {
        _purgeThread.join();
      }
    }

    /// \brief Sets a key-value pair in the cache.
    void set(const K& key, const V& value,
             std::chrono::seconds customTtl = std::chrono::seconds(0))
    {
      auto expiration = std::chrono::steady_clock::now() +
                        (customTtl.count() > 0 ? customTtl : _ttl);
      std::lock_guard<std::mutex> lock(_mutex);
      _cache[key] = {value, expiration};
    }

    /// \brief Gets a value by key from the cache.
    std::optional<V> get(const K& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _cache.find(key);
      if (it != _cache.end() &&
          it->second.expiration > std::chrono::steady_clock::now())
      {
        return it->second.value;
      }
      return std::nullopt;
    }

    /// \brief Removes a key from the cache.
    void remove(const K& key)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _cache.erase(key);
    }

    // Friend accessor for unit testing
    friend struct ExpiringCacheTestAccessor<K, V>;

  private:
    struct CacheEntry
    {
      V value;
      std::chrono::steady_clock::time_point expiration;
    };

    std::unordered_map<K, CacheEntry> _cache;
    std::chrono::seconds _ttl;
    std::mutex _mutex;
    std::thread _purgeThread;
    bool _stop;

    void startPurgeThread()
    {
      _purgeThread = std::thread(
          [this]()
          {
            while (true)
            {
              {
                std::lock_guard<std::mutex> lock(_mutex);
                if (_stop)
                {
                  break;
                }
                auto now = std::chrono::steady_clock::now();
                for (auto it = _cache.begin(); it != _cache.end();)
                {
                  if (it->second.expiration <= now)
                  {
                    it = _cache.erase(it);
                  }
                  else
                  {
                    ++it;
                  }
                }
              }
              std::this_thread::sleep_for(std::chrono::seconds(5));
            }
          });
    }
  };

  /// \brief Provides unit test access to internal state of ExpiringCache.
  template <typename K, typename V> struct ExpiringCacheTestAccessor
  {
    static std::size_t mapSize(ExpiringCache<K, V>& cache)
    {
      std::lock_guard<std::mutex> lock(cache._mutex);
      return cache._cache.size();
    }
  };

  /// \brief Utility for parsing CLI output into key-value pairs or JSON
  /// objects.
  class CliParser
  {
  public:
    /// \brief Parses key-value formatted CLI output.
    static std::unordered_map<std::string, std::string>
    parseKeyValue(const std::string& input)
    {
      std::unordered_map<std::string, std::string> result;
      std::istringstream stream(input);
      std::string line;
      while (std::getline(stream, line))
      {
        auto delimiterPos = line.find('=');
        if (delimiterPos != std::string::npos)
        {
          auto key = line.substr(0, delimiterPos);
          auto value = line.substr(delimiterPos + 1);
          result[key] = value;
        }
      }
      return result;
    }

    /// \brief Parses JSON formatted CLI output.
    static json::Json parseJson(const std::string& input)
    {
      return json::Json::parse(input);
    }
  };

  /// \brief Cross-platform dynamic library loader for plugins.
  class PluginLoader
  {
  public:
    /// \brief Constructor loads the dynamic library from the given path
    PluginLoader(const std::string& path)
    {
#ifdef _WIN32
      _handle = LoadLibraryA(path.c_str());
      if (!_handle)
      {
        throw std::runtime_error("Failed to load library: " + path +
                                 ", error: " + std::to_string(GetLastError()));
      }
#else
      _handle = dlopen(path.c_str(), RTLD_NOW);
      if (!_handle)
      {
        throw std::runtime_error("Failed to load library: " + path +
                                 ", error: " + dlerror());
      }
#endif
      if (!_handle)
      {
        throw std::runtime_error("Failed to load library: " + path);
      }
    }

    /// \brief Destructor closes the dynamic library
    ~PluginLoader()
    {
      if (_handle)
      {
#ifdef _WIN32
        FreeLibrary((HMODULE) _handle);
#else
        dlclose(_handle);
#endif
      }
    }

    /// \brief Resolve a symbol from the loaded library
    /// \tparam T Function or object pointer type
    /// \param name Symbol name to resolve
    /// \return Resolved symbol cast to type T
    template <typename T> T resolve(const std::string& name)
    {
      if (!isValid())
      {
        throw std::runtime_error(
            "Cannot resolve symbol from an invalid library: " + name);
      }

#ifdef _WIN32
      FARPROC symbol = GetProcAddress((HMODULE) _handle, name.c_str());
#else
      void* symbol = dlsym(_handle, name.c_str());
#endif
      if (!symbol)
      {
        throw std::runtime_error("Failed to resolve symbol: " + name);
      }

      _symbolCache[name] = symbol;
      return reinterpret_cast<T>(symbol);
    }

    /// \brief Check whether the library loaded successfully
    bool isValid() const
    {
      return _handle != nullptr;
    }

  private:
    void* _handle = nullptr;
    std::unordered_map<std::string, void*> _symbolCache;
  };

  /// \brief Manages the lifecycle and symbol resolution of multiple dynamically
  /// loaded plugins.
  class PluginManager
  {
  public:
    /// \brief Load a plugin from the given path
    void loadPlugin(const std::string& name, const std::string& path)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      if (_plugins.find(name) != _plugins.end())
      {
        throw std::runtime_error("Plugin already loaded: " + name);
      }

      _plugins[name] = std::make_unique<PluginLoader>(path);
    }

    /// \brief Unload a previously loaded plugin
    void unloadPlugin(const std::string& name)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      auto it = _plugins.find(name);
      if (it != _plugins.end())
      {
        _plugins.erase(it);
      }
    }

    /// \brief Resolve a symbol from a loaded plugin
    /// \tparam T Function or object pointer type
    /// \param name Name of the loaded plugin
    /// \param symbol Symbol name to resolve
    /// \return Resolved symbol cast to type T
    template <typename T>
    T resolve(const std::string& name, const std::string& symbol)
    {
      auto it = _plugins.find(name);
      if (it == _plugins.end())
      {
        throw std::runtime_error("Plugin not loaded: " + name);
      }
      return it->second->resolve<T>(symbol);
    }

    /// \brief Check if a plugin is loaded
    bool isLoaded(const std::string& name) const
    {
      std::lock_guard<std::mutex> lock(_mutex);
      return _plugins.find(name) != _plugins.end();
    }

    /// \brief Unload all loaded plugins
    void unloadAll()
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _plugins.clear();
    }

  private:
    std::map<std::string, std::unique_ptr<PluginLoader>> _plugins;
    mutable std::mutex _mutex; // Protects access to _plugins
  };

} // namespace util

namespace http
{
  /// \brief Estimates or computes token counts for input text, optionally using
  /// external encoders.
  class Tokenizer
  {
  public:
    /// \brief Counts tokens in the input text.
    int count(const std::string& text) const
    {
#ifdef iora_USE_TIKTOKEN
      if (_encoder)
      {
        auto tokens = _encoder->encode(text);
        return static_cast<int>(tokens.size());
      }
#endif
      return estimateFallback(text);
    }

  private:
#ifdef iora_USE_TIKTOKEN
    std::shared_ptr<GptEncoding> _encoder =
        GptEncoding::get_encoding(LanguageModel::CL100K_BASE);
#endif

    int estimateFallback(const std::string& text) const
    {
      int wordCount = 0;
      std::istringstream iss(text);
      std::string token;
      while (iss >> token)
      {
        wordCount++;
      }
      return static_cast<int>(wordCount * 1.5);
    }
  };

  /// \brief Feature-rich HTTP client supporting synchronous, asynchronous, and
  /// streaming API calls.
  class HttpClient
  {
  public:
    /// \brief Performs a GET request with optional headers.
    json::Json get(const std::string& url,
                   const std::map<std::string, std::string>& headers = {},
                   int retries = 0) const
    {
      return retry(
          [&]()
          {
            return cpr::Get(cpr::Url{url},
                            cpr::Header{headers.begin(), headers.end()});
          },
          retries);
    }

    /// \brief Performs a POST request with JSON payload.
    json::Json postJson(const std::string& url, const json::Json& body,
                        const std::map<std::string, std::string>& headers = {},
                        int retries = 0) const
    {
      auto allHeaders = headers;
      allHeaders.emplace("Content-Type", "application/json");

      return retry(
          [&]()
          {
            return cpr::Post(cpr::Url{url}, cpr::Body{body.dump()},
                             cpr::Header{allHeaders.begin(), allHeaders.end()});
          },
          retries);
    }

    /// \brief Performs a POST request with multipart form-data.
    json::Json
    postSingleFile(const std::string& url, const std::string& fileFieldName,
                   const std::string& filePath,
                   const std::map<std::string, std::string>& headers = {},
                   int retries = 0) const
    {
      // Only support a single file part due to cpr::Multipart limitations
      cpr::Multipart multipart{
          cpr::Part{fileFieldName, filePath, "application/octet-stream"}};

      return retry(
          [&]()
          {
            return cpr::Post(cpr::Url{url}, multipart,
                             cpr::Header{headers.begin(), headers.end()});
          },
          retries);
    }

    /// \brief Performs a DELETE request.
    json::Json
    deleteRequest(const std::string& url,
                  const std::map<std::string, std::string>& headers = {},
                  int retries = 0) const
    {
      return retry(
          [&]()
          {
            return cpr::Delete(cpr::Url{url},
                               cpr::Header{headers.begin(), headers.end()});
          },
          retries);
    }

    /// \brief Performs a POST request asynchronously using std::future.
    std::future<json::Json>
    postJsonAsync(const std::string& url, const json::Json& body,
                  const std::map<std::string, std::string>& headers = {},
                  int retries = 0) const
    {
      return std::async(std::launch::async, [=]()
                        { return postJson(url, body, headers, retries); });
    }

    /// \brief Performs a POST request and streams line-delimited responses via
    /// callback.
    void postStream(const std::string& url, const json::Json& body,
                    const std::map<std::string, std::string>& headers,
                    const std::function<void(const std::string&)>& onChunk,
                    int retries = 0) const
    {
      cpr::Response response =
          cpr::Post(cpr::Url{url}, cpr::Body{body.dump()},
                    cpr::Header{headers.begin(), headers.end()},
                    cpr::Header{{"Accept", "text/event-stream"}});

      std::istringstream stream(response.text);
      std::string line;
      while (std::getline(stream, line))
      {
        onChunk(line);
      }
    }

    /// \brief Parses the response as JSON or throws.
    static json::Json parseJsonOrThrow(const cpr::Response& response)
    {
      if (response.status_code < 200 || response.status_code >= 300)
      {
        throw std::runtime_error("HTTP failed with status: " +
                                 std::to_string(response.status_code));
      }

      try
      {
        return json::Json::parse(response.text);
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

  private:
    template <typename Callable>
    json::Json retry(Callable&& action, int retries) const
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
  };

  /// \brief Lightweight, testable HTTP webhook server for handling REST and
  /// JSON endpoints.
  class WebhookServer
  {
  public:
    explicit WebhookServer(int port)
      : _port(port), _server(std::make_unique<httplib::Server>())
    {
    }

    ~WebhookServer() { stop(); }

    void on(const std::string& endpoint,
            const std::function<void(const httplib::Request&,
                                     httplib::Response&)>& handler)
    {
      _server->Post(endpoint.c_str(), handler);
    }

    void onGet(const std::string& endpoint,
               const std::function<void(const httplib::Request&,
                                        httplib::Response&)>& handler)
    {
      _server->Get(endpoint.c_str(), handler);
    }

    void onDelete(const std::string& endpoint,
                  const std::function<void(const httplib::Request&,
                                           httplib::Response&)>& handler)
    {
      _server->Delete(endpoint.c_str(), handler);
    }

    void onJson(const std::string& endpoint,
                const std::function<json::Json(const json::Json&)>& handler)
    {
      _server->Post(
          endpoint.c_str(),
          [handler](const httplib::Request& req, httplib::Response& res)
          {
            try
            {
              json::Json requestJson = json::Json::parse(req.body);
              json::Json responseJson = handler(requestJson);
              res.set_content(responseJson.dump(), "application/json");
            }
            catch (const std::exception& e)
            {
              res.status = 500;
              res.set_content(e.what(), "text/plain");
            }
          });
    }

    void
    onJsonGet(const std::string& endpoint,
              const std::function<json::Json(const httplib::Request&)>& handler)
    {
      _server->Get(
          endpoint.c_str(),
          [handler](const httplib::Request& req, httplib::Response& res)
          {
            try
            {
              json::Json responseJson = handler(req);
              res.set_content(responseJson.dump(), "application/json");
            }
            catch (const std::exception& e)
            {
              res.status = 500;
              res.set_content(e.what(), "text/plain");
            }
          });
    }

    void start() { _server->listen("0.0.0.0", _port); }

    void startAsync()
    {
      _thread = std::thread([this]() { _server->listen("0.0.0.0", _port); });
    }

    void stop()
    {
      _server->stop();
      if (_thread.joinable())
      {
        _thread.join();
      }
    }

  private:
    int _port;
    std::unique_ptr<httplib::Server> _server;
    std::thread _thread;
  };
} // namespace http

namespace log
{

  // Forward declaration
  class LoggerStream;

  /// \brief Thread-safe logger supporting log levels, async mode, file
  /// rotation, and retention.
  class Logger
  {
  public:
    enum class Level
    {
      Trace,
      Debug,
      Info,
      Warning,
      Error,
      Fatal
    };

    struct Endl
    {
    };
    static inline constexpr Endl endl{};

    static void init(Level level = Level::Info,
                     const std::string& filePath = "", bool async = false,
                     int retentionDays = 7,
                     const std::string& timeFormat = "%Y-%m-%d %H:%M:%S")
    {
      std::lock_guard<std::mutex> lock(_mutex);

      _minLevel = level;
      _asyncMode = async;
      _exit = false;
      // If no filePath provided, use default in current directory
      if (filePath.empty())
      {
        _logBasePath = "iora.log";
      }
      else
      {
        _logBasePath = filePath;
      }
      _retentionDays = retentionDays;
      _timestampFormat = timeFormat;
      // Reset current log date so rotateLogFileIfNeeded always opens a new file
      _currentLogDate.clear();
      rotateLogFileIfNeeded();

      if (_asyncMode && !_workerThread.joinable())
      {
        _workerThread = std::thread(runWorker);
      }
    }

    static void flush()
    {
      std::unique_lock<std::mutex> lock(_mutex);
      // Always flush queue for both sync and async modes
      while (!_queue.empty())
      {
        rotateLogFileIfNeeded();
        const std::string& entry = _queue.front();
        std::cout << entry;
        if (_fileStream)
        {
          (*_fileStream) << entry;
          _fileStream->flush();
        }
        _queue.pop();
      }
      // Also flush file stream if open
      if (_fileStream)
      {
        _fileStream->flush();
      }
    }

    static void shutdown()
    {
      flush();
      {
        std::lock_guard<std::mutex> lock(_mutex);
        _exit = true;
      }
      _cv.notify_one();

      if (_workerThread.joinable())
      {
        _workerThread.join();
      }
    }

    static void setLevel(Level level)
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _minLevel = level;
    }

    static void trace(const std::string& message)
    {
      log(Level::Trace, message);
    }
    static void debug(const std::string& message)
    {
      log(Level::Debug, message);
    }
    static void info(const std::string& message) { log(Level::Info, message); }
    static void warning(const std::string& message)
    {
      log(Level::Warning, message);
    }
    static void error(const std::string& message)
    {
      log(Level::Error, message);
    }
    static void fatal(const std::string& message)
    {
      log(Level::Fatal, message);
    }

    static LoggerStream stream(Level level);

    static void log(Level level, const std::string& message)
    {
      if (level < _minLevel)
      {
        return;
      }

      std::ostringstream oss;
      oss << "[" << timestamp() << "] "
          << "[" << levelToString(level) << "] " << message << std::endl;

      std::string output = oss.str();

      if (_asyncMode)
      {
        {
          std::lock_guard<std::mutex> lock(_mutex);
          _queue.push(std::move(output));
        }
        _cv.notify_one();
      }
      else
      {
        std::lock_guard<std::mutex> lock(_mutex);
        rotateLogFileIfNeeded();
        std::cout << output;
        if (_fileStream)
        {
          (*_fileStream) << output;
          _fileStream->flush();
        }
      }
    }

  public:
    friend class LoggerStream;

    static inline std::mutex _mutex;
    static inline std::condition_variable _cv;
    static inline std::queue<std::string> _queue;
    static inline std::thread _workerThread;
    static inline std::atomic<bool> _exit{false};
    static inline bool _asyncMode = false;
    static inline Level _minLevel = Level::Info;
    static inline std::unique_ptr<std::ofstream> _fileStream;
    static inline std::string _logBasePath;
    static inline std::string _currentLogDate;
    static inline int _retentionDays = 7;
    static inline std::string _timestampFormat = "%Y-%m-%d %H:%M:%S";

    static void runWorker()
    {
      while (true)
      {
        std::unique_lock<std::mutex> lock(_mutex);
        _cv.wait(lock, [] { return !_queue.empty() || _exit; });

        while (!_queue.empty())
        {
          rotateLogFileIfNeeded();
          const std::string& entry = _queue.front();
          std::cout << entry;
          if (_fileStream)
          {
            (*_fileStream) << entry;
            _fileStream->flush();
          }
          _queue.pop();
        }

        if (_exit)
        {
          break;
        }
      }
    }

    static std::string timestamp()
    {
      auto now = std::chrono::system_clock::now();
      auto t = std::chrono::system_clock::to_time_t(now);
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()) %
                1000;

      std::ostringstream oss;
      oss << std::put_time(std::localtime(&t), _timestampFormat.c_str());
      if (_timestampFormat.find("%S") != std::string::npos)
      {
        oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
      }
      return oss.str();
    }

    static std::string currentDate()
    {
      auto now = std::chrono::system_clock::now();
      auto t = std::chrono::system_clock::to_time_t(now);
      std::ostringstream oss;
      oss << std::put_time(std::localtime(&t), "%Y-%m-%d");
      return oss.str();
    }

    static void rotateLogFileIfNeeded()
    {
      if (_logBasePath.empty())
      {
        // No log file path specified, skip file logging
        return;
      }

      namespace fs = std::filesystem;
      auto logPath = fs::path(_logBasePath);
      auto logDir = logPath.parent_path();
      // If logDir is empty, use current directory
      if (logDir.empty())
      {
        logDir = fs::current_path();
      }
      if (!fs::exists(logDir))
      {
        std::error_code ec;
        fs::create_directories(logDir, ec);
        if (ec)
        {
          std::cerr << "[Logger] Failed to create log directory: " << logDir
                    << " - " << ec.message() << std::endl;
          return;
        }
      }

      std::string today = currentDate();
      if (today != _currentLogDate)
      {
        _currentLogDate = today;
        std::string rotatedPath = (logDir / (logPath.filename().string() + "." +
                                             _currentLogDate + ".log"))
                                      .string();

        _fileStream =
            std::make_unique<std::ofstream>(rotatedPath, std::ios::app);
        if (!_fileStream->is_open())
        {
          std::cerr << "[Logger] Failed to open rotated log file: "
                    << rotatedPath << std::endl;
          _fileStream.reset();
        }

        deleteOldLogFiles();
      }
    }

    static void deleteOldLogFiles()
    {
      if (_logBasePath.empty() || _retentionDays <= 0)
      {
        return;
      }

      namespace fs = std::filesystem;
      auto now = std::chrono::system_clock::now();
      auto logPath = fs::path(_logBasePath);
      auto logDir = logPath.parent_path();
      if (logDir.empty())
      {
        logDir = fs::current_path();
      }
      std::string baseName = logPath.filename().string();
      std::string prefix = baseName + ".";

      std::error_code dir_ec;
      if (!fs::exists(logDir, dir_ec))
      {
        // Directory does not exist, nothing to delete
        return;
      }

      for (const auto& entry : fs::directory_iterator(logDir, dir_ec))
      {
        if (dir_ec)
        {
          std::cerr << "[Logger] Failed to iterate log directory: " << logDir
                    << " - " << dir_ec.message() << std::endl;
          break;
        }
        const auto& path = entry.path();
        std::string fname = path.filename().string();
        if (fname.find(prefix) != 0 || fname.size() <= prefix.size())
        {
          continue;
        }

        // Extract date from filename: baseName.YYYY-MM-DD.log
        std::string datePart = fname.substr(prefix.size(), 10); // YYYY-MM-DD
        std::tm tm = {};
        std::istringstream ss(datePart);
        ss >> std::get_time(&tm, "%Y-%m-%d");
        if (ss.fail())
        {
          continue;
        }
        auto fileTime =
            std::chrono::system_clock::from_time_t(std::mktime(&tm));
        // Only compare date, not time-of-day
        auto fileDays =
            std::chrono::duration_cast<std::chrono::hours>(now - fileTime)
                .count() /
            24;
        if (fileDays >= _retentionDays)
        {
          std::error_code ec;
          fs::remove(path, ec);
          if (ec)
          {
            std::cerr << "[Logger] Failed to delete old log file: " << path
                      << " - " << ec.message() << std::endl;
          }
        }
      }
    }

    static const char* levelToString(Level level)
    {
      switch (level)
      {
      case Level::Trace:
        return "TRACE";
      case Level::Debug:
        return "DEBUG";
      case Level::Info:
        return "INFO";
      case Level::Warning:
        return "WARN";
      case Level::Error:
        return "ERROR";
      case Level::Fatal:
        return "FATAL";
      default:
        return "UNKNOWN";
      }
    }
  };

  /// \brief Stream interface for composing and emitting log messages with
  /// levels.
  class LoggerStream
  {
  public:
    explicit LoggerStream(Logger::Level level) : _level(level), _flushed(false)
    {
    }

    template <typename T> LoggerStream& operator<<(const T& value)
    {
      _stream << value;
      return *this;
    }

    LoggerStream& operator<<(Logger::Endl)
    {
      flush();
      return *this;
    }

    ~LoggerStream()
    {
      if (!_flushed && !_stream.str().empty())
      {
        flush();
      }
    }

  private:
    Logger::Level _level;
    std::ostringstream _stream;
    bool _flushed;

    void flush()
    {
      Logger::log(_level, _stream.str());
      _flushed = true;
      // Ensure log content is flushed to disk for tests
      iora::log::Logger::flush();
    }
  };

  /// \brief Proxy for streaming log messages at specific log levels.
  class LoggerProxy
  {
  public:
    LoggerStream operator<<(Logger::Level level)
    {
      return Logger::stream(level);
    }
  };

  inline LoggerProxy Logger;

#define LOG_CONTEXT_PREFIX                                                     \
  "[" << __FILE__ << ":" << __LINE__ << " " << __func__ << "] "

#define LOG_WITH_LEVEL(level, msg)                                             \
  do                                                                           \
  {                                                                            \
    iora::log::Logger << iora::log::Logger::Level::level << LOG_CONTEXT_PREFIX \
                      << msg << iora::log::Logger::endl;                       \
  } while (0)

#define LOG_TRACE(msg) LOG_WITH_LEVEL(Trace, msg)
#define LOG_DEBUG(msg) LOG_WITH_LEVEL(Debug, msg)
#define LOG_INFO(msg) LOG_WITH_LEVEL(Info, msg)
#define LOG_WARN(msg) LOG_WITH_LEVEL(Warning, msg)
#define LOG_ERROR(msg) LOG_WITH_LEVEL(Error, msg)
#define LOG_FATAL(msg) LOG_WITH_LEVEL(Fatal, msg)

  inline LoggerStream Logger::stream(Logger::Level level)
  {
    return LoggerStream(level);
  }
} // namespace log

namespace shell
{
  /// \brief Executes shell commands and captures their output as strings.
  class ShellRunner
  {
  public:
    /// \brief Executes a shell command.
    /// \param command The shell command to execute.
    /// \return The output of the command.
    static std::string execute(const std::string& command)
    {
      try
      {
        auto result = subprocess::check_output({"/bin/sh", "-c", command});
        return std::string(result.buf.data(), result.length);
      }
      catch (const std::exception& e)
      {
        throw std::runtime_error("ShellRunner error: " + std::string(e.what()));
      }
    }
  };
} // namespace shell

/// \brief Singleton entry point for the Iora library, managing all core
/// components and providing factory methods for utilities and plugins.
class IoraService : public util::PluginManager
{
public:
  /// \brief Cleans up all global Iora resources, notifies plugins, and unloads
  /// shared libraries. Should be called at program exit or at the end of
  /// main().
  static void shutdown()
  {
    IoraService& svc = instance();
    // Notify all loaded plugins before unloading libraries
    for (auto* plugin : svc._loadedModules)
    {
      if (plugin)
      {
        try
        {
          plugin->onUnload();
        }
        catch (...)
        { /* swallow */
        }
      }
    }
    svc._loadedModules.clear();
    // Unload all plugin libraries
    // Flush the JSON file store
    if (svc._jsonFileStore)
    {
      svc._jsonFileStore->flush();
    }
    svc.unloadAll();
    // Stop the webhook server if running
    svc.stopWebhookServer();
    // Flush and shutdown logger
    log::Logger::shutdown();
    // (Optionally) clear other global resources, caches, etc.
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
  };

  /// \brief Retrieves the global instance of the service.
  static IoraService& instance()
  {
    static IoraService instance;
    return instance;
  }

  /// \brief Initialises the singleton with command‑line arguments.
  ///        Supported options: `--port/-p`, `--config/-c`, `--state-file/-s`,
  ///        `--log-level/-l`, `--log-file/-f`, `--log-async`,
  ///        `--log-retention`, and `--log-time-format`.
  ///        CLI values always override the configuration file.
  static IoraService& init(int argc, char** argv)
  {
    IoraService& svc = instance();
    svc.parseCommandLine(argc, argv);
    return svc;
  }

  /// \brief Deleted copy constructor and assignment operator.
  IoraService(const IoraService&) = delete;
  IoraService& operator=(const IoraService&) = delete;

  /// \brief Starts the embedded webhook server on its configured port.
  void startWebhookServer()
  {
    if (!_serverRunning)
    {
      _webhookServer->startAsync(); // Use -> to access the method
      _serverRunning = true;
    }
  }

  /// \brief Stops the embedded webhook server if it is running.
  void stopWebhookServer()
  {
    if (_serverRunning)
    {
      _webhookServer->stop(); // Use -> to access the method
      _serverRunning = false;
    }
  }

  /// \brief Accessor for the webhook server.
  http::WebhookServer& webhookServer()
  {
    return *_webhookServer; // Dereference the unique_ptr to return the
                            // underlying object
  }

  /// \brief Accessor for the in-memory state store.
  state::ConcreteStateStore& stateStore() { return _stateStore; }

  /// \brief Accessor for the expiring cache.
  util::ExpiringCache<std::string, std::string>& cache() { return _cache; }

  /// \brief Accessor for the configuration loader.
  config::ConfigLoader& configLoader() { return _configLoader; }

  /// \brief Accessor for the embedded JSON file store.
  const std::unique_ptr<state::JsonFileStore>& jsonFileStore() const
  {
    return _jsonFileStore;
  }

  /// \brief Factory for creating a JSON file store backed by the given file.
  std::unique_ptr<state::JsonFileStore>
  makeJsonFileStore(const std::string& filename) const
  {
    return std::make_unique<state::JsonFileStore>(filename);
  }

  /// \brief Factory for creating a new stateless HTTP client.
  http::HttpClient makeHttpClient() const { return http::HttpClient{}; }

  /// \brief Push an event to the EventQueue
  void pushEvent(const json::Json& event) { _eventQueue.push(event); }

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
  void registerPluginApi(const std::string& name, Func&& func)
  {
    std::lock_guard<std::mutex> lock(_apiMutex);
    using func_type = std::decay_t<Func>;
    using signature = decltype(&func_type::operator());
    _pluginApis[name] = makeStdFunction(std::forward<Func>(func), signature{});
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
  std::function<FuncSignature> getPluginApi(const std::string& name)
  {
    std::lock_guard<std::mutex> lock(_apiMutex);
    auto it = _pluginApis.find(name);
    if (it == _pluginApis.end())
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
  Ret callPluginApi(const std::string& name, Args&&... args)
  {
    auto func = getPluginApi<Ret(Args...)>(name);
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

private:
  // For main thread blocking/termination
  std::mutex _terminationMutex;
  std::condition_variable _terminationCv;
  bool _terminated = false;
  // Track loaded plugin instances for proper onUnload notification
  std::vector<Plugin*> _loadedModules;
  /// \brief Private constructor initialises members and loads configuration.
  IoraService()
    : _port(8080),
      _webhookServer(std::make_unique<http::WebhookServer>(8080)),
      _stateStore(),
      _cache(std::chrono::seconds{60}),
      _configLoader("config.toml"),
      _serverRunning(false)
  {
    // Load configuration from file and override defaults.
    try
    {
      toml::table config = _configLoader.load();
      if (auto serverTable = config["server"].as_table())
      {
        if (auto portVal = serverTable->get("port"))
        {
          if (auto portInt = portVal->as_integer())
          {
            _port = static_cast<int>(portInt->get());
          }
        }
      }
      if (auto stateTable = config["state"].as_table())
      {
        if (auto fileVal = stateTable->get("file"))
        {
          if (auto fileStr = fileVal->as_string())
          {
            _jsonFileStore =
                std::make_unique<state::JsonFileStore>(fileStr->get());
          }
        }
      }
    }
    catch (const std::exception&)
    {
      // Ignore configuration errors and fall back to defaults.
    }
    // Reconstruct webhook server if the port changed.
    _webhookServer = std::make_unique<http::WebhookServer>(_port);
  }

  /// \brief Private destructor stops the server.
  ~IoraService() { stopWebhookServer(); }

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
    const std::vector<std::string> supportedExtensions = {".so", ".dll"};
    for (const auto& entry : std::filesystem::directory_iterator(modulesPath))
    {
      if (entry.is_regular_file() &&
          std::find(supportedExtensions.begin(), supportedExtensions.end(),
                    entry.path().extension()) != supportedExtensions.end())
      {
        try
        {
          std::string pluginName = entry.path().filename().string();
          LOG_INFO("Loading plugin: " + pluginName);
          loadPlugin(pluginName, entry.path().string());

          // Resolve and call the exported loadModule function
          using LoadModuleFunc = Plugin* (*) (iora::IoraService*);
          auto loadModule = resolve<LoadModuleFunc>(pluginName, "loadModule");
          Plugin* pluginInstance = loadModule(this);
          if (pluginInstance)
          {
            _loadedModules.push_back(pluginInstance);
          }
        }
        catch (const std::exception& e)
        {
          LOG_ERROR("Failed to load plugin: " + entry.path().string() + " - " +
                    e.what());
        }
      }
    }
    LOG_INFO("Module loading complete.");
  }

  /// \brief Parses command‑line arguments and overrides configuration
  /// accordingly.
  void parseCommandLine(int argc, char** argv)
  {
    // Holders for command-line overrides.
    std::optional<int> cliPort;
    std::optional<std::string> cliConfigPath;
    std::optional<std::string> cliStateFile;
    std::optional<std::string> cliLogLevel;
    std::optional<std::string> cliLogFile;
    std::optional<bool> cliLogAsync;
    std::optional<int> cliLogRetention;
    std::optional<std::string> cliLogTimeFormat;

    // Scan the arguments to capture CLI values.
    for (int i = 1; i < argc; ++i)
    {
      std::string arg = argv[i];
      if ((arg == "-p" || arg == "--port") && i + 1 < argc)
      {
        try
        {
          cliPort = std::stoi(argv[++i]);
        }
        catch (...)
        {
        }
      }
      else if ((arg == "-c" || arg == "--config") && i + 1 < argc)
      {
        cliConfigPath = std::string{argv[++i]};
      }
      else if ((arg == "-s" || arg == "--state-file") && i + 1 < argc)
      {
        cliStateFile = std::string{argv[++i]};
      }
      else if ((arg == "-l" || arg == "--log-level") && i + 1 < argc)
      {
        cliLogLevel = std::string{argv[++i]};
      }
      else if ((arg == "-f" || arg == "--log-file") && i + 1 < argc)
      {
        cliLogFile = std::string{argv[++i]};
      }
      else if ((arg == "-m" || arg == "--modules") && i + 1 < argc)
      {
        _modulesPath = std::string{argv[++i]};
      }
      else if (arg == "--log-async" && i + 1 < argc)
      {
        std::string val = std::string{argv[++i]};
        std::transform(val.begin(), val.end(), val.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(std::tolower(c)); });
        if (val == "true" || val == "1" || val == "yes")
        {
          cliLogAsync = true;
        }
        else if (val == "false" || val == "0" || val == "no")
        {
          cliLogAsync = false;
        }
      }
      else if (arg == "--log-retention" && i + 1 < argc)
      {
        try
        {
          cliLogRetention = std::stoi(argv[++i]);
        }
        catch (...)
        {
        }
      }
      else if (arg == "--log-time-format" && i + 1 < argc)
      {
        cliLogTimeFormat = std::string{argv[++i]};
      }
      // Unrecognised arguments are ignored.
    }

    // Holders for values loaded from the configuration file.
    std::optional<std::string> cfgLogLevel;
    std::optional<std::string> cfgLogFile;
    std::optional<bool> cfgLogAsync;
    std::optional<int> cfgLogRetention;
    std::optional<std::string> cfgLogTimeFormat;

    // If a config file was specified, load it and update defaults.
    if (cliConfigPath)
    {
      _configLoader = config::ConfigLoader{*cliConfigPath};
      try
      {
        toml::table cfg = _configLoader.load();
        if (auto serverTable = cfg["server"].as_table())
        {
          if (auto portVal = serverTable->get("port"))
          {
            if (auto portInt = portVal->as_integer())
            {
              _port = static_cast<int>(portInt->get());
            }
          }
        }
        if (auto serverTable = cfg["modules"].as_table())
        {
          if (auto modulesVal = serverTable->get("directory"))
          {
            if (auto modulesStr = modulesVal->as_string())
            {
              if (_modulesPath.empty())
              {
                _modulesPath = modulesStr->get();
              }
            }
          }
        }
        if (auto stateTable = cfg["state"].as_table())
        {
          if (auto fileVal = stateTable->get("file"))
          {
            if (auto fileStr = fileVal->as_string())
            {
              _jsonFileStore =
                  std::make_unique<state::JsonFileStore>(fileStr->get());
            }
          }
        }
        if (auto logTable = cfg["log"].as_table())
        {
          if (auto levelVal = logTable->get("level"))
          {
            if (auto levelStr = levelVal->as_string())
            {
              cfgLogLevel = levelStr->get();
            }
          }
          if (auto fileVal = logTable->get("file"))
          {
            if (auto fileStr = fileVal->as_string())
            {
              cfgLogFile = fileStr->get();
            }
          }
          if (auto asyncVal = logTable->get("async"))
          {
            if (auto asyncBool = asyncVal->as_boolean())
            {
              cfgLogAsync = asyncBool->get();
            }
          }
          if (auto retentionVal = logTable->get("retention_days"))
          {
            if (auto retentionInt = retentionVal->as_integer())
            {
              cfgLogRetention = static_cast<int>(retentionInt->get());
            }
          }
          if (auto formatVal = logTable->get("time_format"))
          {
            if (auto formatStr = formatVal->as_string())
            {
              cfgLogTimeFormat = formatStr->get();
            }
          }
        }
      }
      catch (...)
      {
        // Ignore errors and keep defaults.
      }
    }

    // Apply explicit overrides for server port and state file.
    if (cliPort)
    {
      _port = *cliPort;
    }

    if (cliStateFile)
    {
      _jsonFileStore = std::make_unique<state::JsonFileStore>(*cliStateFile);
    }
    else if (!_jsonFileStore)
    {
      // If no state file was specified, use the default.
      _jsonFileStore = std::make_unique<state::JsonFileStore>("state.json");
    }

    // Reconstruct the webhook server if the port has changed.
    _webhookServer = std::make_unique<http::WebhookServer>(_port);

    // Default logger settings based on Logger::init
    // signature:contentReference[oaicite:1]{index=1}.
    log::Logger::Level finalLevel = log::Logger::Level::Info;
    std::string finalFile;
    bool finalAsync = false;
    int finalRetention = 7;
    std::string finalTimeFormat = "%Y-%m-%d %H:%M:%S";

    // Convert a log-level string to an enum (case-insensitive).
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
      {
        return log::Logger::Level::Trace;
      }
      if (v == "debug")
      {
        return log::Logger::Level::Debug;
      }
      if (v == "warn" || v == "warning")
      {
        return log::Logger::Level::Warning;
      }
      if (v == "error")
      {
        return log::Logger::Level::Error;
      }
      if (v == "fatal")
      {
        return log::Logger::Level::Fatal;
      }
      return log::Logger::Level::Info;
    };

    // Apply config-file values.
    if (cfgLogLevel)
    {
      finalLevel = toLevel(*cfgLogLevel);
    }
    if (cfgLogFile)
    {
      finalFile = *cfgLogFile;
    }
    if (cfgLogAsync)
    {
      finalAsync = *cfgLogAsync;
    }
    if (cfgLogRetention)
    {
      finalRetention = *cfgLogRetention;
    }
    if (cfgLogTimeFormat)
    {
      finalTimeFormat = *cfgLogTimeFormat;
    }

    // Override with CLI values.
    if (cliLogLevel)
    {
      finalLevel = toLevel(*cliLogLevel);
    }
    if (cliLogFile)
    {
      finalFile = *cliLogFile;
    }
    if (cliLogAsync)
    {
      finalAsync = *cliLogAsync;
    }
    if (cliLogRetention)
    {
      finalRetention = *cliLogRetention;
    }
    if (cliLogTimeFormat)
    {
      finalTimeFormat = *cliLogTimeFormat;
    }

    // Initialise the logger.  This sets the log level, file base path,
    // asynchronous mode, retention days and time
    // format:contentReference[oaicite:2]{index=2}.
    log::Logger::init(finalLevel, finalFile, finalAsync, finalRetention,
                      finalTimeFormat);

    loadModules();
  }

  int _port;
  std::unique_ptr<http::WebhookServer> _webhookServer;
  state::ConcreteStateStore _stateStore;
  util::ExpiringCache<std::string, std::string> _cache;
  config::ConfigLoader _configLoader;
  std::unique_ptr<state::JsonFileStore> _jsonFileStore;
  bool _serverRunning;
  std::string _modulesPath;

  /// \brief EventQueue for managing and dispatching events
  util::EventQueue _eventQueue{4}; // Default to 4 worker threads

  std::unordered_map<std::string, std::any> _pluginApis;
  std::mutex _apiMutex;
};

class IoraService::RouteBuilder
{
public:
  RouteBuilder(http::WebhookServer& server, const std::string& endpoint)
    : _server(server), _endpoint(endpoint)
  {
  }

  void handleJson(const std::function<json::Json(const json::Json&)>& handler)
  {
    _server.onJson(_endpoint, handler);
  }

private:
  http::WebhookServer& _server;
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
      static PluginType instance(service);                                     \
      instance.onLoad(service);                                                \
      return &instance;                                                        \
    }                                                                          \
    catch (const std::exception& e)                                            \
    {                                                                          \
      iora::log::Logger::error("Plugin initialization failed: " +              \
                               std::string(e.what()));                         \
      return nullptr;                                                          \
    }                                                                          \
  }

} // namespace iora