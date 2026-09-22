// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
#include "iora/core/logger.hpp"
#include "iora/parsers/json.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

namespace iora
{
namespace storage
{

/// \brief Thread-safe key-value store backed by a JSON file with background
/// flushing and persistence.
///
/// A single background thread (shared across every live instance) flushes each
/// dirty store to disk on a configurable interval; flush() forces an immediate
/// write, and the destructor flushes on teardown. Persistence is periodic (not
/// per-write): a failed write keeps the store dirty so the next flush retries it.
///
/// Lock ordering (outer -> inner; never acquired in reverse):
///   lifecycleMutex()  -> flushCycleMutex() -> registryMutex() -> _mutex
///   lifecycleMutex()  -> terminateCvMutex()   (register/unregister set shouldExit)
/// The background flush thread holds flushCycleMutex() for a whole flush cycle
/// (snapshot + I/O), takes registryMutex() only to snapshot, then each store's
/// _mutex; it NEVER takes lifecycleMutex(). terminateCvMutex() is only ever held
/// alone (the CV wait) or nested directly under lifecycleMutex(); it is never
/// co-held with flushCycleMutex()/registryMutex(). So there is no lock cycle.
///
/// Lifetime precondition: every JsonFileStore must be destroyed before process
/// exit. A leaked instance keeps the registry non-empty, so the shared flush
/// thread is never joined and its function-local-static std::thread destructs
/// joinable at exit -> std::terminate.
class JsonFileStore
{
public:
  /// \brief Construct and load JSON file if it exists
  explicit JsonFileStore(std::string filename) : _filename(std::move(filename)), _dirty(false)
  {
    iora::core::Logger::info("JsonFileStore: Initializing with file: " + _filename);
    std::ifstream file(_filename);
    if (file)
    {
      try
      {
        file >> _store;
        // The whole API assumes an object store (set/get/remove index by key). A
        // file that parses to an array/scalar would make erase()/operator[] throw,
        // so coerce a non-object load to an empty object (matching the missing-file
        // and parse-failure paths below).
        if (!_store.isObject())
        {
          iora::core::Logger::error("JsonFileStore: " + _filename +
                                    " did not contain a JSON object - starting with empty store");
          _store = parsers::Json::object();
        }
        else
        {
          iora::core::Logger::info("JsonFileStore: Loaded existing data with " +
                                   std::to_string(_store.size()) + " keys from: " + _filename);
        }
      }
      catch (const std::exception &e)
      {
        iora::core::Logger::error("JsonFileStore: Failed to parse JSON from " + _filename + ": " +
                                  e.what() + " - starting with empty store");
        _store = parsers::Json::object();
      }
    }
    else
    {
      iora::core::Logger::info("JsonFileStore: File " + _filename +
                               " does not exist, starting with empty store");
      _store = parsers::Json::object();
    }

    registerStore();
  }

  /// \brief Destructor unregisters the store then flushes any pending changes.
  ~JsonFileStore()
  {
    iora::core::Logger::debug("JsonFileStore: Destructor called for " + _filename);
    // unregisterStore() removes this from the registry AND drains any in-flight
    // flush cycle that could still hold a pointer to this, BEFORE any member is
    // destroyed; the final flush() then runs with this no longer reachable by
    // the background thread.
    unregisterStore();
    flush();
    iora::core::Logger::debug("JsonFileStore: Cleanup completed for " + _filename);
  }

  /// \brief Set a key to a value and mark store dirty
  template <typename T> void set(const std::string &key, const T &value)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    bool isUpdate = _store.contains(key);
    _store[key] = value;
    _dirty = true;
    iora::core::Logger::debug(std::string("JsonFileStore: ") + (isUpdate ? "Updated" : "Added") +
                              " key '" + key + "' in " + _filename +
                              " (total keys: " + std::to_string(_store.size()) + ")");
  }

  /// \brief Specialization for std::string
  void set(const std::string &key, const std::string &value)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    bool isUpdate = _store.contains(key);
    _store[key] = value;
    _dirty = true;
    iora::core::Logger::debug(std::string("JsonFileStore: ") + (isUpdate ? "Updated" : "Added") +
                              " string key '" + key + "' in " + _filename +
                              " (value length: " + std::to_string(value.length()) +
                              " chars, total keys: " + std::to_string(_store.size()) + ")");
  }

  /// \brief Get a value from the store
  template <typename T> std::optional<T> get(const std::string &key) const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_store.contains(key))
    {
      try
      {
        auto val = _store[key].get<T>();
        iora::core::Logger::debug("JsonFileStore: Retrieved value for key '" + key + "' from " +
                                  _filename);
        return val;
      }
      catch (const std::exception &e)
      {
        iora::core::Logger::error("JsonFileStore: Type conversion failed for key '" + key +
                                  "' in " + _filename + ": " + e.what());
        return std::nullopt;
      }
    }
    iora::core::Logger::debug("JsonFileStore: Key '" + key + "' not found in " + _filename);
    return std::nullopt;
  }

  /// \brief Specialization for std::string
  std::optional<std::string> get(const std::string &key) const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_store.contains(key))
    {
      try
      {
        auto val = _store[key].get<std::string>();
        iora::core::Logger::debug("JsonFileStore: Retrieved string value for key '" + key +
                                  "' from " + _filename +
                                  " (length: " + std::to_string(val.length()) + " chars)");
        return val;
      }
      catch (const std::exception &e)
      {
        iora::core::Logger::error("JsonFileStore: String conversion failed for key '" + key +
                                  "' in " + _filename + ": " + e.what());
        return std::nullopt;
      }
    }
    iora::core::Logger::debug("JsonFileStore: String key '" + key + "' not found in " + _filename);
    return std::nullopt;
  }

  /// \brief Remove a key from the store and mark dirty
  void remove(const std::string &key)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_store.erase(key) > 0)
    {
      _dirty = true;
      iora::core::Logger::debug("JsonFileStore: Removed key '" + key + "' from " + _filename +
                                " (remaining keys: " + std::to_string(_store.size()) + ")");
    }
    else
    {
      iora::core::Logger::debug("JsonFileStore: Attempted to remove non-existent key '" + key +
                                "' from " + _filename);
    }
  }

  /// \brief Immediately write the store to disk. A failed write keeps the store
  /// dirty so the next flush (explicit or background) retries it.
  void flush()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_dirty)
    {
      iora::core::Logger::debug("JsonFileStore: Flushing " + std::to_string(_store.size()) +
                                " keys to " + _filename);
      if (writeAndClearLocked())
      {
        iora::core::Logger::debug("JsonFileStore: Flush completed for " + _filename);
      }
      else
      {
        iora::core::Logger::error("JsonFileStore: Flush FAILED for " + _filename +
                                  " - keeping changes dirty for retry");
      }
    }
    else
    {
      iora::core::Logger::debug("JsonFileStore: No changes to flush for " + _filename);
    }
  }

  /// \brief Configure the background flush interval (in milliseconds). Written
  /// under terminateCvMutex() and notified; the running wait's timeout is not
  /// shortened, so the new interval takes effect on the NEXT wait cycle. This is
  /// the single interval shared by every instance.
  static void setFlushInterval(std::chrono::milliseconds interval)
  {
    {
      std::lock_guard<std::mutex> lock(terminateCvMutex());
      flushInterval() = interval;
    }
    terminationCv().notify_all();
  }

  /// \brief The shared background flush interval. Public read accessor (a config
  /// query); prefer setFlushInterval() to CHANGE it (that write is serialized
  /// under terminateCvMutex). The remaining shared-machinery accessors are
  /// private (internal).
#if defined(IORA_CORE_SHARED) || defined(IORA_CORE_BUILDING)
  static std::chrono::milliseconds &flushInterval();
#else
  static std::chrono::milliseconds &flushInterval()
  {
    static std::chrono::milliseconds ms{2000};
    return ms;
  }
#endif

private:
  // Shared, process-global background-flush machinery. Private (internal): only
  // setFlushInterval() and the read accessor flushInterval() above are the public
  // surface; these mutexes/thread/registry are internal. In a shared-library build
  // they are declared here and defined once in the core translation unit so
  // libiora_core.so and every plugin resolve to a single instance (access control
  // does not apply to the out-of-line definitions); otherwise they are inline
  // function-local statics with a well-defined construction/destruction order.
#if defined(IORA_CORE_SHARED) || defined(IORA_CORE_BUILDING)
  static std::set<JsonFileStore *> &registry();
  static std::mutex &registryMutex();
  static std::mutex &lifecycleMutex();
  static std::mutex &flushCycleMutex();
  static std::thread &flushThread();
  static std::condition_variable &terminationCv();
  static std::mutex &terminateCvMutex();
  static std::atomic<bool> &shouldExit();
#else
  static std::set<JsonFileStore *> &registry()
  {
    static std::set<JsonFileStore *> s;
    return s;
  }
  // Guards registry() membership. Held only briefly (insert/erase/snapshot);
  // NOT held across file I/O (see flushThreadFunc / flushCycleMutex).
  static std::mutex &registryMutex()
  {
    static std::mutex m;
    return m;
  }
  // Serializes the thread spawn/join lifecycle in registerStore/unregisterStore.
  // The flush thread NEVER acquires this, so holding it across join() cannot
  // deadlock against the flush loop.
  static std::mutex &lifecycleMutex()
  {
    static std::mutex m;
    return m;
  }
  // Held by the flush thread for a whole flush cycle (snapshot + I/O).
  // unregisterStore() acquires it after erasing an instance from the registry,
  // to drain any in-flight cycle that may still hold a pointer to that instance
  // -- this is what makes the copy-then-flush loop free of use-after-free while
  // keeping file I/O off registryMutex.
  static std::mutex &flushCycleMutex()
  {
    static std::mutex m;
    return m;
  }
  static std::thread &flushThread()
  {
    static std::thread t;
    return t;
  }
  static std::condition_variable &terminationCv()
  {
    static std::condition_variable cv;
    return cv;
  }
  static std::mutex &terminateCvMutex()
  {
    static std::mutex m;
    return m;
  }
  static std::atomic<bool> &shouldExit()
  {
    static std::atomic<bool> flag{false};
    return flag;
  }
#endif

private:
  /// \brief Write the store to disk. Returns true on success, false on any
  /// open/serialization/write failure (logged). The caller decides what to do
  /// with the dirty flag; a false return must NOT clear it.
  bool saveToFile() const
  {
    try
    {
      std::ofstream file(_filename);
      if (!file)
      {
        iora::core::Logger::error("JsonFileStore: Failed to open " + _filename + " for writing");
        return false;
      }
      std::string jsonData = _store.dump(2);
      file << jsonData;
      if (!file)
      {
        iora::core::Logger::error("JsonFileStore: Write error on " + _filename);
        return false;
      }
      iora::core::Logger::debug("JsonFileStore: Wrote " + std::to_string(jsonData.length()) +
                                " bytes to " + _filename);
      return true;
    }
    catch (const std::exception &e)
    {
      iora::core::Logger::error("JsonFileStore: Failed to write to " + _filename + ": " + e.what());
      return false;
    }
  }

  /// \brief Write the store and clear _dirty ONLY on success. Precondition:
  /// caller holds _mutex and has already confirmed _dirty. Shared by flush() and
  /// tryFlushIfDirty() so both keep the identical no-silent-loss discipline.
  bool writeAndClearLocked()
  {
    if (saveToFile())
    {
      _dirty = false;
      return true;
    }
    return false; // keep _dirty for retry
  }

  /// \brief Background-tick flush for one store.
  void tryFlushIfDirty()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_dirty)
    {
      iora::core::Logger::debug("JsonFileStore: Background flush triggered for " + _filename);
      writeAndClearLocked(); // failure keeps _dirty for the next tick (no silent drop)
    }
  }

  /// \brief Register this instance and start the shared flush thread if it is
  /// the first live instance. The whole spawn/join lifecycle is serialized by
  /// lifecycleMutex() (which the flush thread never takes). On a thread-spawn
  /// failure the registry insert is rolled back so a failed construction leaves
  /// no dangling entry (which would permanently wedge the first-instance-spawns
  /// pattern).
  void registerStore()
  {
    std::lock_guard<std::mutex> life(lifecycleMutex());
    bool wasEmpty;
    {
      std::lock_guard<std::mutex> reg(registryMutex());
      wasEmpty = registry().empty();
      registry().insert(this);
    }
    if (wasEmpty)
    {
      // A previously-stopped thread is non-joinable after unregisterStore()'s
      // join(); reap it defensively before assigning a fresh one (assigning to
      // a joinable std::thread would call std::terminate).
      if (flushThread().joinable())
      {
        flushThread().join();
      }
      {
        std::lock_guard<std::mutex> cv(terminateCvMutex());
        shouldExit().store(false);
      }
      try
      {
        flushThread() = std::thread(flushThreadFunc);
      }
      catch (...)
      {
        // Spawn failed: roll back the insert so this (whose construction is
        // failing) does not remain a dangling registry entry. NOTE: this rollback
        // path and the concurrent-setFlushInterval-vs-running-wait path are not
        // unit-tested (both need fault/timing injection with no production seam);
        // both were verified by code review.
        std::lock_guard<std::mutex> reg(registryMutex());
        registry().erase(this);
        throw;
      }
    }
  }

  /// \brief Unregister this instance and stop the shared flush thread if it was
  /// the last one. After erasing, it DRAINS any in-flight flush cycle (via
  /// flushCycleMutex) so the flusher cannot dereference this after the dtor frees
  /// it. join() runs holding only lifecycleMutex (registryMutex/flushCycleMutex/
  /// terminateCvMutex all released first), so it cannot deadlock the flush thread.
  void unregisterStore()
  {
    std::lock_guard<std::mutex> life(lifecycleMutex());
    bool nowEmpty;
    {
      std::lock_guard<std::mutex> reg(registryMutex());
      registry().erase(this);
      nowEmpty = registry().empty();
    }
    // Drain: block until any in-flight flush cycle that may hold a copied
    // pointer to `this` (snapshotted before the erase above) has finished. A
    // cycle starting after the erase snapshots the registry without `this`.
    {
      std::lock_guard<std::mutex> cyc(flushCycleMutex());
    }
    if (nowEmpty)
    {
      {
        std::lock_guard<std::mutex> cv(terminateCvMutex());
        shouldExit().store(true);
      }
      terminationCv().notify_all();
      if (flushThread().joinable())
      {
        flushThread().join();
      }
    }
  }

  /// \brief The single shared flush worker. Waits (predicate-form) for the
  /// interval or a stop signal, then flushes every dirty store. It holds
  /// flushCycleMutex for the WHOLE cycle (so unregisterStore can drain it),
  /// takes registryMutex only to snapshot the live pointers, and performs file
  /// I/O with registryMutex RELEASED -- so REGISTRATION (registryMutex) is never
  /// blocked by disk I/O. UNregistration deliberately drains an in-flight cycle
  /// via flushCycleMutex, so destroying an instance can wait out a cycle's I/O;
  /// that drain is what closes the lifetime window.
  ///
  /// shouldExit() uses default seq_cst: it is a cold stop flag (checked a few
  /// times per interval), publishes no non-atomic data (teardown visibility comes
  /// from terminateCvMutex + join), so relaxed would also be correct; seq_cst is
  /// kept for clarity as this is not a hot path.
  static void flushThreadFunc()
  {
    for (;;)
    {
      {
        std::unique_lock<std::mutex> lock(terminateCvMutex());
        terminationCv().wait_for(lock, flushInterval(), [] { return shouldExit().load(); });
      }
      if (shouldExit().load())
      {
        break;
      }

      // Take flushCycleMutex BEFORE snapshotting, and hold it across the I/O:
      // unregisterStore() erases under registryMutex then blocks on
      // flushCycleMutex, so a store present in this snapshot cannot be destroyed
      // until this cycle completes.
      std::lock_guard<std::mutex> cyc(flushCycleMutex());
      std::vector<JsonFileStore *> snapshot;
      {
        std::lock_guard<std::mutex> reg(registryMutex());
        snapshot.assign(registry().begin(), registry().end());
      }
      for (auto *store : snapshot)
      {
        if (shouldExit().load())
        {
          break;
        }
        try
        {
          store->tryFlushIfDirty();
        }
        catch (...)
        {
          // A single store's failure (incl. a Logger/std::system_error throw)
          // must not abort the shared thread and std::terminate the process.
        }
      }
    }
  }

  const std::string _filename;
  mutable std::mutex _mutex; // innermost; guards _store + _dirty
  parsers::Json _store;
  bool _dirty;
  // All shared statics are function-local (or defined once in the core TU) for
  // safe destruction order. See the class-level Lock ordering note.
};

} // namespace storage
} // namespace iora
