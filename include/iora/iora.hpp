#pragma once

#include <iostream>
#include <stdexcept>
#include <string>
#include "subprocess.hpp"
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

#ifdef iora_USE_TIKTOKEN
#include <tiktoken/encodings.h>
#endif

namespace iora
{
namespace config
{
  /// \brief Loads configuration from TOML files.
  class ConfigLoader
  {
  public:
    /// \brief Constructs a ConfigLoader with the given filename.
    /// \param filename The path to the TOML configuration file.
    explicit ConfigLoader(const std::string& filename) : _filename(filename) {}

    /// \brief Loads the TOML configuration file.
    /// \return A toml::table representing the configuration.
    toml::table load() const { return toml::parse_file(_filename); }

  private:
    std::string _filename;
  };
} // namespace config

namespace state
{
  /// \brief A simple key-value state store.
  class ConcreteStateStore
  {
  public:
    /// \brief Sets a key-value pair in the store.
    void set(const std::string& key, const std::string& value)
    {
      _store[key] = value;
    }

    /// \brief Gets a value by key from the store.
    std::optional<std::string> get(const std::string& key) const
    {
      auto it = _store.find(key);
      if (it != _store.end())
      {
        return it->second;
      }
      return std::nullopt;
    }

  private:
    std::unordered_map<std::string, std::string> _store;
  };

  /// \brief A JSON file-backed key-value store.
  class JsonFileStore
  {
  public:
    explicit JsonFileStore(const std::string& filename) : _filename(filename) {}

    void set(const std::string& key, const std::string& value)
    {
      _store[key] = value;
      saveToFile();
    }

    std::optional<std::string> get(const std::string& key) const
    {
      if (_store.contains(key))
      {
        return _store[key].get<std::string>();
      }
      return std::nullopt;
    }

    void remove(const std::string& key)
    {
      _store.erase(key);
      saveToFile();
    }

  private:
    void saveToFile() const
    {
      std::ofstream file(_filename);
      file << _store.dump(4);
    }

    std::string _filename;
    nlohmann::json _store;
  };
} // namespace state

namespace util
{
  // Forward declaration for friend accessor
  template <typename K, typename V> struct ExpiringCacheTestAccessor;
  /// \brief A thread-safe cache with time-to-live (TTL) and automatic purging.
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

  // Friend accessor struct for unit testing ExpiringCache
  /// \brief Friend accessor struct for unit testing ExpiringCache
  template <typename K, typename V> struct ExpiringCacheTestAccessor
  {
    static std::size_t mapSize(ExpiringCache<K, V>& cache)
    {
      std::lock_guard<std::mutex> lock(cache._mutex);
      return cache._cache.size();
    }
  };

  /// \brief Parses CLI output into key-value pairs or JSON.
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
    static nlohmann::json parseJson(const std::string& input)
    {
      return nlohmann::json::parse(input);
    }
  };
} // namespace util

/// JSON type alias to avoid exposing third-party namespaces.
using Json = nlohmann::json;

namespace http
{
  /// \brief Optional tokenizer class for estimating or computing exact token
  /// counts.
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

  /// Lightweight and feature-rich header-only HTTP client for sync and async
  /// API calls.
  class HttpClient
  {
  public:
    /// \brief Performs a GET request with optional headers.
    Json get(const std::string& url,
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
    Json postJson(const std::string& url, const Json& body,
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
    Json postSingleFile(const std::string& url,
                        const std::string& fileFieldName,
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
    Json deleteRequest(const std::string& url,
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
    std::future<Json>
    postJsonAsync(const std::string& url, const Json& body,
                  const std::map<std::string, std::string>& headers = {},
                  int retries = 0) const
    {
      return std::async(std::launch::async, [=]()
                        { return postJson(url, body, headers, retries); });
    }

    /// \brief Performs a POST request and streams line-delimited responses via
    /// callback.
    void postStream(const std::string& url, const Json& body,
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
    static Json parseJsonOrThrow(const cpr::Response& response)
    {
      if (response.status_code < 200 || response.status_code >= 300)
      {
        throw std::runtime_error("HTTP failed with status: " +
                                 std::to_string(response.status_code));
      }

      try
      {
        return Json::parse(response.text);
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
    Json retry(Callable&& action, int retries) const
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

  /// \brief A simple and testable webhook server.
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
                const std::function<Json(const Json&)>& handler)
    {
      _server->Post(
          endpoint.c_str(),
          [handler](const httplib::Request& req, httplib::Response& res)
          {
            try
            {
              Json requestJson = Json::parse(req.body);
              Json responseJson = handler(requestJson);
              res.set_content(responseJson.dump(), "application/json");
            }
            catch (const std::exception& e)
            {
              res.status = 500;
              res.set_content(e.what(), "text/plain");
            }
          });
    }

    void onJsonGet(const std::string& endpoint,
                   const std::function<Json(const httplib::Request&)>& handler)
    {
      _server->Get(
          endpoint.c_str(),
          [handler](const httplib::Request& req, httplib::Response& res)
          {
            try
            {
              Json responseJson = handler(req);
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

  /// \brief Logger for logging messages with levels, async, rotation, and
  /// retention.
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

  /// \brief LoggerStream for streaming log messages.
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

  /// \brief LoggerProxy for streaming log levels.
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
  /// \brief Executes shell commands and captures their output.
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

/// \brief Header-only singleton that encapsulates all functionality
///        provided by the Iora library.  It owns and manages stateful
///        components (HTTP server, configuration loader, caches and stores)
///        and provides factory methods for stateless utilities such as the
///        HTTP client and JSON file stores.
class IoraService
{
public:
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
  state::JsonFileStore& jsonFileStore() { return _jsonFileStore; }

  /// \brief Factory for creating a JSON file store backed by the given file.
  state::JsonFileStore makeJsonFileStore(const std::string& filename) const
  {
    return state::JsonFileStore{filename};
  }

  /// \brief Factory for creating a new stateless HTTP client.
  http::HttpClient makeHttpClient() const { return http::HttpClient{}; }

private:
  /// \brief Private constructor initialises members and loads configuration.
  IoraService()
    : _port(8080),
      _webhookServer(std::make_unique<http::WebhookServer>(8080)),
      _stateStore(),
      _cache(std::chrono::seconds{60}),
      _configLoader("config.toml"),
      _jsonFileStore("state.json"),
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
            _jsonFileStore = state::JsonFileStore{fileStr->get()};
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
      else if (arg == "--log-async" && i + 1 < argc)
      {
        std::string val = std::string{argv[++i]};
        std::transform(val.begin(), val.end(), val.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(std::tolower(c)); });
        if (val == "true" || val == "1" || val == "yes")
          cliLogAsync = true;
        else if (val == "false" || val == "0" || val == "no")
          cliLogAsync = false;
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
              _port = static_cast<int>(portInt->get());
          }
        }
        if (auto stateTable = cfg["state"].as_table())
        {
          if (auto fileVal = stateTable->get("file"))
          {
            if (auto fileStr = fileVal->as_string())
              _jsonFileStore = state::JsonFileStore{fileStr->get()};
          }
        }
        if (auto logTable = cfg["log"].as_table())
        {
          if (auto levelVal = logTable->get("level"))
          {
            if (auto levelStr = levelVal->as_string())
              cfgLogLevel = levelStr->get();
          }
          if (auto fileVal = logTable->get("file"))
          {
            if (auto fileStr = fileVal->as_string())
              cfgLogFile = fileStr->get();
          }
          if (auto asyncVal = logTable->get("async"))
          {
            if (auto asyncBool = asyncVal->as_boolean())
              cfgLogAsync = asyncBool->get();
          }
          if (auto retentionVal = logTable->get("retention_days"))
          {
            if (auto retentionInt = retentionVal->as_integer())
              cfgLogRetention = static_cast<int>(retentionInt->get());
          }
          if (auto formatVal = logTable->get("time_format"))
          {
            if (auto formatStr = formatVal->as_string())
              cfgLogTimeFormat = formatStr->get();
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
      _port = *cliPort;
    if (cliStateFile)
      _jsonFileStore = state::JsonFileStore{*cliStateFile};

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
        return log::Logger::Level::Trace;
      if (v == "debug")
        return log::Logger::Level::Debug;
      if (v == "warn" || v == "warning")
        return log::Logger::Level::Warning;
      if (v == "error")
        return log::Logger::Level::Error;
      if (v == "fatal")
        return log::Logger::Level::Fatal;
      return log::Logger::Level::Info;
    };

    // Apply config-file values.
    if (cfgLogLevel)
      finalLevel = toLevel(*cfgLogLevel);
    if (cfgLogFile)
      finalFile = *cfgLogFile;
    if (cfgLogAsync)
      finalAsync = *cfgLogAsync;
    if (cfgLogRetention)
      finalRetention = *cfgLogRetention;
    if (cfgLogTimeFormat)
      finalTimeFormat = *cfgLogTimeFormat;

    // Override with CLI values.
    if (cliLogLevel)
      finalLevel = toLevel(*cliLogLevel);
    if (cliLogFile)
      finalFile = *cliLogFile;
    if (cliLogAsync)
      finalAsync = *cliLogAsync;
    if (cliLogRetention)
      finalRetention = *cliLogRetention;
    if (cliLogTimeFormat)
      finalTimeFormat = *cliLogTimeFormat;

    // Initialise the logger.  This sets the log level, file base path,
    // asynchronous mode, retention days and time
    // format:contentReference[oaicite:2]{index=2}.
    log::Logger::init(finalLevel, finalFile, finalAsync, finalRetention,
                      finalTimeFormat);
  }

  int _port;
  std::unique_ptr<http::WebhookServer> _webhookServer;
  state::ConcreteStateStore _stateStore;
  util::ExpiringCache<std::string, std::string> _cache;
  config::ConfigLoader _configLoader;
  state::JsonFileStore _jsonFileStore;
  bool _serverRunning;
};

} // namespace iora
