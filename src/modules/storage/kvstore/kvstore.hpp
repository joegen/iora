// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef __unix__
#include <fcntl.h>
#include <unistd.h>
#endif

/// @brief Maximum length for keys in KVStore
/// This is set to 65535 bytes, which is the maximum length for a key in the KVStore.
/// Keys longer than this will throw an exception.
/// Values can be up to 100 * 1024 * 1024 bytes in size.
static constexpr size_t MAX_KEY_LENGTH = 65535;
static constexpr size_t MAX_VALUE_LENGTH = 100 * 1024 * 1024;

/// Configuration options for KVStore
struct KVStoreConfig
{
  uint32_t magicNumber = 0xB1A2C3D4;
  uint32_t version = 1;
  uint32_t maxLogSizeBytes = 10 * 1024 * 1024;
  uint32_t maxCacheSize = 1000;
  bool enableBackgroundCompaction = true;
  std::chrono::milliseconds compactionInterval{30000};
};

/// Exception thrown for KVStore-specific errors
class KVStoreException : public std::runtime_error
{
public:
  explicit KVStoreException(const std::string &msg) : std::runtime_error(msg) {}
};

/// \brief A robust binary persistent key-value store with atomic operations, concurrent reads, and
/// background compaction.
class KVStore
{
public:
  explicit KVStore(const std::string &path, const KVStoreConfig &config = {})
      : _config(config), _path(path), _logPath(path + ".log"), _tempPath(path + ".tmp"),
        _shutdown(false), _compactionInProgress(false)
  {
    try
    {
      load();
      openLogFile();
      if (_config.enableBackgroundCompaction)
      {
        _compactionThread = std::thread(&KVStore::compactionWorker, this);
      }
    }
    catch (const std::exception &e)
    {
      throw KVStoreException("Failed to initialize KVStore: " + std::string(e.what()));
    }
  }

  ~KVStore()
  {
    try
    {
      shutdown();
    }
    catch (...)
    {
      // Destructor should not throw
    }
  }

  void setString(const std::string &key, const std::string &value)
  {
    set(key, std::vector<std::uint8_t>(value.begin(), value.end()));
  }

  std::optional<std::string> getString(const std::string &key)
  {
    auto binary = get(key);
    if (binary.has_value())
    {
      return std::string(binary->begin(), binary->end());
    }
    return std::nullopt;
  }

  void set(const std::string &key, const std::vector<std::uint8_t> &value)
  {
    if (key.empty())
    {
      throw KVStoreException("Key cannot be empty");
    }
    // Enforce key and value size limits (key: 65535, value: 100MB)
    if (key.size() > MAX_KEY_LENGTH)
    {
      throw KVStoreException("Key too large");
    }
    if (value.size() > MAX_VALUE_LENGTH)
    {
      throw KVStoreException("Value too large");
    }

    std::unique_lock<std::shared_mutex> lock(_mutex);
    _kv[key] = value;
    updateCache(key, value);

    try
    {
      writeLogEntry('S', key, value);
    }
    catch (const std::exception &e)
    {
      _kv.erase(key);
      _cache.erase(key);
      throw KVStoreException("Failed to write log entry: " + std::string(e.what()));
    }

    maybeCompact();
  }

  std::optional<std::vector<std::uint8_t>> get(const std::string &key)
  {
    if (key.empty())
    {
      return std::nullopt;
    }

    // Check cache first
    {
      std::shared_lock<std::shared_mutex> cacheLock(_cacheMutex);
      auto cacheIt = _cache.find(key);
      if (cacheIt != _cache.end())
      {
        return cacheIt->second;
      }
    }

    std::shared_lock<std::shared_mutex> lock(_mutex);
    auto it = _kv.find(key);
    if (it != _kv.end())
    {
      updateCache(key, it->second);
      return it->second;
    }
    return std::nullopt;
  }

  void remove(const std::string &key)
  {
    if (key.empty())
    {
      return;
    }

    std::unique_lock<std::shared_mutex> lock(_mutex);
    if (_kv.erase(key) > 0)
    {
      {
        std::unique_lock<std::shared_mutex> cacheLock(_cacheMutex);
        _cache.erase(key);
      }

      try
      {
        writeLogEntry('D', key, {});
      }
      catch (const std::exception &e)
      {
        throw KVStoreException("Failed to write delete log entry: " + std::string(e.what()));
      }

      maybeCompact();
    }
  }

  // Batch operations for better performance
  void setBatch(const std::unordered_map<std::string, std::vector<std::uint8_t>> &batch)
  {
    if (batch.empty())
      return;

    for (const auto &[key, value] : batch)
    {
      if (key.empty() || key.size() > MAX_KEY_LENGTH || value.size() > MAX_VALUE_LENGTH)
      {
        throw KVStoreException("Invalid key or value in batch operation");
      }
    }

    std::unique_lock<std::shared_mutex> lock(_mutex);

    // Apply all changes to memory first
    for (const auto &[key, value] : batch)
    {
      _kv[key] = value;
      updateCache(key, value);
    }

    // Then write to log
    try
    {
      for (const auto &[key, value] : batch)
      {
        writeLogEntry('S', key, value);
      }
    }
    catch (const std::exception &e)
    {
      // Rollback memory changes
      for (const auto &[key, value] : batch)
      {
        _kv.erase(key);
        _cache.erase(key);
      }
      throw KVStoreException("Failed to write batch log entries: " + std::string(e.what()));
    }

    maybeCompact();
  }

  std::unordered_map<std::string, std::vector<std::uint8_t>>
  getBatch(const std::vector<std::string> &keys)
  {
    std::unordered_map<std::string, std::vector<std::uint8_t>> result;
    std::shared_lock<std::shared_mutex> lock(_mutex);

    for (const auto &key : keys)
    {
      if (!key.empty())
      {
        auto it = _kv.find(key);
        if (it != _kv.end())
        {
          result[key] = it->second;
        }
      }
    }

    return result;
  }

  void flush()
  {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    if (_logStream.is_open())
    {
      _logStream.flush();
#ifdef __unix__
      // Get file descriptor properly
      // std::ofstream* ofs = &_logStream;
      // auto* filebuf = static_cast<std::filebuf*>(ofs->rdbuf());
      // Use lower-level approach to get fd
      int fd = open(_logPath.c_str(), O_WRONLY | O_APPEND);
      if (fd != -1)
      {
        fsync(fd);
        close(fd);
      }
#endif
    }
  }

  void compact()
  {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    _compactionInProgress = true;

    try
    {
      // Create snapshot with proper error handling
      {
        std::ofstream out(_tempPath, std::ios::binary | std::ios::trunc);
        if (!out.is_open())
        {
          throw KVStoreException("Failed to open temp file for compaction: " + _tempPath);
        }

        // Write header with validation
        if (!writeHeader(out))
        {
          throw KVStoreException("Failed to write header during compaction");
        }

        uint32_t count = static_cast<uint32_t>(_kv.size());
        if (!out.write(reinterpret_cast<const char *>(&count), sizeof(count)))
        {
          throw KVStoreException("Failed to write count during compaction");
        }

        // Write all key-value pairs with validation
        for (const auto &[key, value] : _kv)
        {
          if (!writeKeyValue(out, key, value))
          {
            throw KVStoreException("Failed to write key-value pair during compaction");
          }
        }

        out.flush();
        if (!out.good())
        {
          throw KVStoreException("Stream error during compaction");
        }
      }

      // Atomic rename operation
      std::error_code ec;
      std::filesystem::rename(_tempPath, _path, ec);
      if (ec)
      {
        std::filesystem::remove(_tempPath, ec); // Cleanup
        throw KVStoreException("Failed to rename temp file: " + ec.message());
      }

      // Reset log file
      _logStream.close();
      {
        std::ofstream clearLog(_logPath, std::ios::trunc);
        if (!clearLog.is_open())
        {
          throw KVStoreException("Failed to clear log file");
        }
      }

      openLogFile();
    }
    catch (const std::exception &e)
    {
      _compactionInProgress = false;
      std::error_code ec;
      std::filesystem::remove(_tempPath, ec); // Cleanup on failure
      throw;
    }

    _compactionInProgress = false;
  }

  // Statistics and utility methods
  size_t size() const
  {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _kv.size();
  }

  bool exists(const std::string &key) const
  {
    if (key.empty())
      return false;
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _kv.find(key) != _kv.end();
  }

  void forceCompact() { compact(); }

  // Shutdown method for proper cleanup
  void shutdown()
  {
    _shutdown = true;
    _compactionCV.notify_all();

    if (_compactionThread.joinable())
    {
      _compactionThread.join();
    }

    flush();
    _logStream.close();
  }

  KVStore(const KVStore &) = delete;
  KVStore &operator=(const KVStore &) = delete;
  KVStore(KVStore &&) = delete;
  KVStore &operator=(KVStore &&) = delete;

private:
  // Helper methods for atomic operations
  bool writeHeader(std::ofstream &out) const
  {
    return out.write(reinterpret_cast<const char *>(&_config.magicNumber),
                     sizeof(_config.magicNumber)) &&
           out.write(reinterpret_cast<const char *>(&_config.version), sizeof(_config.version));
  }

  bool writeKeyValue(std::ofstream &out, const std::string &key,
                     const std::vector<std::uint8_t> &value) const
  {
    uint32_t keyLen = static_cast<uint32_t>(key.size());
    uint32_t valLen = static_cast<uint32_t>(value.size());

    return out.write(reinterpret_cast<const char *>(&keyLen), sizeof(keyLen)) &&
           out.write(key.data(), keyLen) &&
           out.write(reinterpret_cast<const char *>(&valLen), sizeof(valLen)) &&
           out.write(reinterpret_cast<const char *>(value.data()), valLen);
  }

  void openLogFile()
  {
    _logStream.open(_logPath, std::ios::binary | std::ios::app);
    if (!_logStream.is_open())
    {
      throw KVStoreException("Failed to open log file: " + _logPath);
    }
  }

  // Background compaction worker
  void compactionWorker()
  {
    while (!_shutdown)
    {
      std::unique_lock<std::mutex> lock(_compactionMutex);
      _compactionCV.wait_for(lock, _config.compactionInterval, [this] { return _shutdown.load(); });

      if (_shutdown)
        break;

      try
      {
        if (shouldCompact())
        {
          compact();
        }
      }
      catch (const std::exception &e)
      {
        // Log error but continue - don't crash the background thread
      }
    }
  }

  bool shouldCompact() const
  {
    std::error_code ec;
    return std::filesystem::exists(_logPath, ec) && !ec &&
           std::filesystem::file_size(_logPath, ec) > _config.maxLogSizeBytes && !ec;
  }

  void maybeCompact()
  {
    if (!_config.enableBackgroundCompaction && shouldCompact())
    {
      compact();
    }
  }

  // Cache management
  void updateCache(const std::string &key, const std::vector<std::uint8_t> &value) const
  {
    std::unique_lock<std::shared_mutex> lock(_cacheMutex);
    if (_cache.size() >= _config.maxCacheSize)
    {
      // Simple LRU eviction - remove first element
      _cache.erase(_cache.begin());
    }
    _cache[key] = value;
  }

  // Enhanced CRC32 with input validation
  uint32_t crc32(const std::vector<std::uint8_t> &data) const
  {
    if (data.empty())
      return 0;

    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t b : data)
    {
      crc ^= b;
      for (int i = 0; i < 8; ++i)
      {
        if (crc & 1)
          crc = (crc >> 1) ^ 0xEDB88320;
        else
          crc >>= 1;
      }
    }
    return ~crc;
  }

  // Enhanced corruption detection
  bool validateLogEntry(const std::vector<std::uint8_t> &buffer, size_t expectedSize) const
  {
    if (buffer.size() < 10)
      return false; // Minimum size check
    if (buffer.size() != expectedSize)
      return false;

    // Additional integrity checks can be added here
    return true;
  }

  void load()
  {
    // Load snapshot with robust error handling
    std::ifstream snapshot(_path, std::ios::binary);
    if (snapshot.is_open())
    {
      uint32_t magic = 0;
      if (!snapshot.read(reinterpret_cast<char *>(&magic), sizeof(magic)) ||
          magic != _config.magicNumber)
      {
        throw KVStoreException("Invalid or corrupted snapshot file: bad magic number");
      }

      uint32_t version = 0;
      if (!snapshot.read(reinterpret_cast<char *>(&version), sizeof(version)) ||
          version != _config.version)
      {
        throw KVStoreException("Unsupported snapshot version: " + std::to_string(version));
      }

      uint32_t count = 0;
      if (!snapshot.read(reinterpret_cast<char *>(&count), sizeof(count)))
      {
        throw KVStoreException("Failed to read entry count from snapshot");
      }

      if (count > 10000000) // Sanity check
      {
        throw KVStoreException("Unreasonable entry count in snapshot: " + std::to_string(count));
      }

      for (uint32_t i = 0; i < count; ++i)
      {
        uint32_t keyLen = 0;
        if (!snapshot.read(reinterpret_cast<char *>(&keyLen), sizeof(keyLen)) || keyLen == 0 ||
            keyLen > 65536)
        {
          throw KVStoreException("Invalid key length in snapshot at entry " + std::to_string(i));
        }

        std::string key(keyLen, '\0');
        if (!snapshot.read(&key[0], keyLen))
        {
          throw KVStoreException("Failed to read key in snapshot at entry " + std::to_string(i));
        }

        uint32_t valLen = 0;
        if (!snapshot.read(reinterpret_cast<char *>(&valLen), sizeof(valLen)) ||
            valLen > 100 * 1024 * 1024)
        {
          throw KVStoreException("Invalid value length in snapshot at entry " + std::to_string(i));
        }

        std::vector<std::uint8_t> value(valLen);
        if (!snapshot.read(reinterpret_cast<char *>(value.data()), valLen))
        {
          throw KVStoreException("Failed to read value in snapshot at entry " + std::to_string(i));
        }

        _kv[std::move(key)] = std::move(value);
      }
    }

    // Load log with enhanced error handling and corruption detection
    std::ifstream log(_logPath, std::ios::binary);
    if (!log.is_open())
      return; // No log file yet

    size_t entriesProcessed = 0;
    while (log.peek() != EOF)
    {
      uint32_t totalLen = 0;
      if (!log.read(reinterpret_cast<char *>(&totalLen), sizeof(totalLen)) || totalLen < 10 ||
          totalLen > 100 * 1024 * 1024)
      {
        break; // Invalid or corrupted entry
      }

      std::vector<std::uint8_t> buffer(totalLen);
      if (!log.read(reinterpret_cast<char *>(buffer.data()), totalLen))
      {
        break; // Incomplete entry
      }

      if (!validateLogEntry(buffer, totalLen))
      {
        continue; // Skip corrupted entry
      }

      const char *ptr = reinterpret_cast<const char *>(buffer.data());
      char op = *ptr++;

      if (op != 'S' && op != 'D')
      {
        continue; // Unknown operation
      }

      uint32_t keyLen;
      std::memcpy(&keyLen, ptr, 4);
      ptr += 4;

      if (keyLen == 0 || keyLen > 65536 ||
          ptr + keyLen > reinterpret_cast<const char *>(buffer.data()) + buffer.size())
      {
        continue; // Invalid key length
      }

      std::string key(ptr, keyLen);
      ptr += keyLen;

      if (op == 'S')
      {
        uint32_t valLen;
        if (ptr + 4 > reinterpret_cast<const char *>(buffer.data()) + buffer.size())
        {
          continue;
        }
        std::memcpy(&valLen, ptr, 4);
        ptr += 4;

        if (valLen > 100 * 1024 * 1024 ||
            ptr + valLen + 4 > reinterpret_cast<const char *>(buffer.data()) + buffer.size())
        {
          continue; // Invalid value length
        }

        std::vector<std::uint8_t> value(valLen);
        std::memcpy(value.data(), ptr, valLen);
        ptr += valLen;

        uint32_t storedCrc;
        std::memcpy(&storedCrc, ptr, 4);

        // Verify CRC
        std::vector<std::uint8_t> payload(buffer.begin(), buffer.end() - 4);
        if (crc32(payload) != storedCrc)
        {
          continue; // CRC mismatch, skip entry
        }

        _kv[key] = value;
      }
      else if (op == 'D')
      {
        _kv.erase(key);
      }

      entriesProcessed++;
    }
  }

  void writeLogEntry(char op, const std::string &key, const std::vector<std::uint8_t> &value)
  {
    if (!_logStream.is_open())
    {
      throw KVStoreException("Log stream is not open");
    }

    std::vector<std::uint8_t> buffer;
    buffer.reserve(1 + 4 + key.size() + (op == 'S' ? 4 + value.size() : 0)); // Pre-allocate

    buffer.push_back(static_cast<uint8_t>(op));
    uint32_t keyLen = static_cast<uint32_t>(key.size());
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t *>(&keyLen),
                  reinterpret_cast<const uint8_t *>(&keyLen) + 4);
    buffer.insert(buffer.end(), key.begin(), key.end());

    if (op == 'S')
    {
      uint32_t valLen = static_cast<uint32_t>(value.size());
      buffer.insert(buffer.end(), reinterpret_cast<const uint8_t *>(&valLen),
                    reinterpret_cast<const uint8_t *>(&valLen) + 4);
      buffer.insert(buffer.end(), value.begin(), value.end());
    }

    uint32_t checksum = crc32(buffer);
    uint32_t totalLen = static_cast<uint32_t>(buffer.size()) + 4; // +4 for checksum

    // Write atomically
    if (!_logStream.write(reinterpret_cast<const char *>(&totalLen), 4) ||
        !_logStream.write(reinterpret_cast<const char *>(buffer.data()), buffer.size()) ||
        !_logStream.write(reinterpret_cast<const char *>(&checksum), 4))
    {
      throw KVStoreException("Failed to write log entry");
    }

    _logStream.flush();
  }

  // Configuration and paths
  const KVStoreConfig _config;
  const std::string _path;
  const std::string _logPath;
  const std::string _tempPath;

  // File streams
  std::ofstream _logStream;

  // Data storage
  std::unordered_map<std::string, std::vector<std::uint8_t>> _kv;
  mutable std::unordered_map<std::string, std::vector<std::uint8_t>> _cache;

  // Threading and synchronization
  mutable std::shared_mutex _mutex;
  mutable std::shared_mutex _cacheMutex;
  std::mutex _compactionMutex;
  std::condition_variable _compactionCV;
  std::thread _compactionThread;

  // State management
  std::atomic<bool> _shutdown;
  std::atomic<bool> _compactionInProgress;
};

// Convenience alias for easier usage
using KVStore = KVStore;