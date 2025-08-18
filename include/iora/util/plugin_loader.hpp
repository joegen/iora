// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
#include <iostream>
#include <stdexcept>
#include <string>
#include <mutex>
#include <unordered_map>
#include <memory>
#include <map>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace iora
{
namespace util
{

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
} // namespace iora
