#pragma once
#include <fstream>
#include <mutex>
#include <set>
#include <thread>
#include <condition_variable>
#include "iora/core/json.hpp"
#include "iora/core/logger.hpp"

namespace iora {
namespace storage {

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
          _store = core::Json::object();
        }
      }
      else
      {
        _store = core::Json::object();
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
          auto val = _store[key].get<T>();
          return val;
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
          auto val = _store[key].get<std::string>();
          return val;
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
    static std::set<JsonFileStore*>& registry()
    {
      static std::set<JsonFileStore*> s;
      return s;
    }
    static std::mutex& registryMutex()
    {
      static std::mutex m;
      return m;
    }
    static std::thread& flushThread()
    {
      static std::thread t;
      return t;
    }
    static std::chrono::milliseconds& flushInterval()
    {
      static std::chrono::milliseconds ms{2000};
      return ms;
    }
    static std::condition_variable& terminationCv()
    {
      static std::condition_variable cv;
      return cv;
    }
    static std::mutex& terminateCvMutex()
    {
      static std::mutex m;
      return m;
    }
    static void setFlushInterval(std::chrono::milliseconds interval)
    {
      flushInterval() = interval;
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
      std::lock_guard<std::mutex> lock(registryMutex());
      registry().insert(this);
      if (registry().size() == 1)
      {
        flushThread() = std::thread(flushThreadFunc);
      }
    }

    void unregisterStore()
    {
      std::lock_guard<std::mutex> lock(registryMutex());
      registry().erase(this);
      if (registry().empty())
      {
        LOG_INFO("No more stores registered, stopping flush thread");
        terminationCv().notify_all();
        if (flushThread().joinable())
        {
          flushThread().join();
        }
        flushThread() = std::thread(); // Reset thread
        LOG_INFO("Flush thread stopped");
      }
    }

    static void flushThreadFunc()
    {
      while (true)
      {
        {
          std::unique_lock<std::mutex> lock(terminateCvMutex());
          if (terminationCv().wait_for(lock, flushInterval()) != std::cv_status::timeout)
          {
            // Notified to exit
            break;
          }
        }
        for (auto* store : registry())
        {
          store->tryFlushIfDirty();
        }
      }
    }

    const std::string _filename;
    mutable std::mutex _mutex;
    core::Json _store;
    bool _dirty;
    // All statics are now function-local for safe destruction order
  };

} } // namespace iora::state