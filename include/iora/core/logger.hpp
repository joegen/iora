// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace iora
{
// Namespace log
namespace core
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

  /// \brief External log handler function type
  /// Takes log level, formatted message, and original message without timestamp/level prefix
  using ExternalHandler = std::function<void(Level level, const std::string &formattedMessage,
                                             const std::string &rawMessage)>;

  struct Endl
  {
  };
  static inline constexpr Endl endl{};

  static void init(Level level = Level::Info, const std::string &filePath = "", bool async = false,
                   int retentionDays = 7, const std::string &timeFormat = "%Y-%m-%d %H:%M:%S")
  {
    auto &data = getData();
    std::lock_guard<std::mutex> lock(data.mutex);

    data.minLevel = level;
    data.asyncMode = async;
    data.exit = false;
    // If no filePath provided, use default in current directory
    if (filePath.empty())
    {
      data.logBasePath = "iora.log";
    }
    else
    {
      data.logBasePath = filePath;
    }
    data.retentionDays = retentionDays;
    data.timestampFormat = timeFormat;
    // Reset current log date so rotateLogFileIfNeeded always opens a new file
    data.currentLogDate.clear();
    rotateLogFileIfNeeded();

    if (data.asyncMode && !data.workerThread.joinable())
    {
      data.workerThread = std::thread(runWorker);
    }
  }

  static void flush()
  {
    auto &data = getData();
    std::unique_lock<std::mutex> lock(data.mutex);

    // Flush external handler queue first
    while (!data.rawQueue.empty() && data.useExternalHandler && data.externalHandler)
    {
      auto [level, rawMessage] = data.rawQueue.front();
      data.rawQueue.pop();

      // Format the message for external handler
      std::string formattedMessage = formatLogMessage(level, rawMessage);

      // Temporarily unlock to call external handler
      lock.unlock();
      data.externalHandler(level, formattedMessage, rawMessage);
      lock.lock();
    }

    // Always flush queue for both sync and async modes
    while (!data.queue.empty())
    {
      rotateLogFileIfNeeded();
      const std::string &entry = data.queue.front();

      if (data.fileStream)
      {
        (*data.fileStream) << entry;
        data.fileStream->flush();
      }
      else
      {
        std::cout << entry;
      }
      data.queue.pop();
    }
    // Also flush file stream if open
    if (data.fileStream)
    {
      data.fileStream->flush();
    }
  }

  static void shutdown()
  {
    flush();
    auto &data = getData();
    {
      std::lock_guard<std::mutex> lock(data.mutex);
      data.exit = true;
    }
    data.cv.notify_one();

    if (data.workerThread.joinable())
    {
      data.workerThread.join();
    }
  }

  static void setLevel(Level level)
  {
    auto &data = getData();
    std::lock_guard<std::mutex> lock(data.mutex);
    data.minLevel = level;
  }

  /// \brief Register an external log handler
  /// When an external handler is registered, file logging and console output are disabled
  /// \param handler The external handler function to register
  static void setExternalHandler(ExternalHandler handler)
  {
    auto &data = getData();
    std::lock_guard<std::mutex> lock(data.mutex);
    data.externalHandler = std::move(handler);
    data.useExternalHandler = true;

    // Close file stream when external handler is active
    if (data.fileStream && data.fileStream->is_open())
    {
      data.fileStream->close();
      data.fileStream.reset();
    }
  }

  /// \brief Remove external log handler and restore normal logging
  static void clearExternalHandler()
  {
    auto &data = getData();
    std::lock_guard<std::mutex> lock(data.mutex);
    data.externalHandler = nullptr;
    data.useExternalHandler = false;
    // File logging will be restored on next log call via rotateLogFileIfNeeded
  }

  /// \brief Set the log format string (thread-safe)
  /// Supported placeholders:
  ///   %T - timestamp (uses timestampFormat from init())
  ///   %t - thread ID
  ///   %L - log level (e.g., INFO, DEBUG, ERROR)
  ///   %m - message content
  ///   %% - literal percent sign
  /// \param format The format string (default: "[%T] [%L] %m")
  /// Example with thread ID: "[%T] [%t] [%L] %m"
  /// \note Format is pre-compiled for performance; parsing happens only on this call.
  /// \note Empty format strings are ignored.
  static void setLogFormat(const std::string &format)
  {
    if (format.empty())
    {
      return;
    }
    auto &data = getData();
    std::lock_guard<std::mutex> lock(data.mutex);
    data._logFormat = format;
    compileFormat(format, data._compiledFormat);
  }

  /// \brief Get the current log format string
  /// \return The current log format string
  static std::string getLogFormat()
  {
    auto &data = getData();
    std::lock_guard<std::mutex> lock(data.mutex);
    return data._logFormat;
  }

  static void trace(const std::string &message) { log(Level::Trace, message); }
  static void debug(const std::string &message) { log(Level::Debug, message); }
  static void info(const std::string &message) { log(Level::Info, message); }
  static void warning(const std::string &message) { log(Level::Warning, message); }
  static void error(const std::string &message) { log(Level::Error, message); }
  static void fatal(const std::string &message) { log(Level::Fatal, message); }

  /// \brief Printf-style logging methods with automatic buffer sizing
  /// These methods support printf-style formatting with no message length limit.
  /// Buffer is automatically sized to fit the formatted output.
  /// \note Does NOT include context info (file/line/function). Use IORA_LOG_*F macros for context.
  /// \note Compile-time format checking enabled for GCC/Clang via __attribute__((format)).
  /// \param fmt Printf-style format string
  /// \param ... Variable arguments matching format specifiers
#if defined(__GNUC__) || defined(__clang__)
  __attribute__((format(printf, 1, 2)))
#endif
  static void tracef(const char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    logFormatted(Level::Trace, fmt, args);
    va_end(args);
  }

#if defined(__GNUC__) || defined(__clang__)
  __attribute__((format(printf, 1, 2)))
#endif
  static void debugf(const char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    logFormatted(Level::Debug, fmt, args);
    va_end(args);
  }

#if defined(__GNUC__) || defined(__clang__)
  __attribute__((format(printf, 1, 2)))
#endif
  static void infof(const char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    logFormatted(Level::Info, fmt, args);
    va_end(args);
  }

#if defined(__GNUC__) || defined(__clang__)
  __attribute__((format(printf, 1, 2)))
#endif
  static void warningf(const char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    logFormatted(Level::Warning, fmt, args);
    va_end(args);
  }

#if defined(__GNUC__) || defined(__clang__)
  __attribute__((format(printf, 1, 2)))
#endif
  static void errorf(const char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    logFormatted(Level::Error, fmt, args);
    va_end(args);
  }

#if defined(__GNUC__) || defined(__clang__)
  __attribute__((format(printf, 1, 2)))
#endif
  static void fatalf(const char *fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    logFormatted(Level::Fatal, fmt, args);
    va_end(args);
  }

  static LoggerStream stream(Level level);

  static void log(Level level, const std::string &message)
  {
    auto &data = getData();
    if (level < data.minLevel)
    {
      return;
    }

    std::string output = formatLogMessage(level, message);

    if (data.asyncMode)
    {
      {
        std::lock_guard<std::mutex> lock(data.mutex);
        if (data.useExternalHandler)
        {
          data.rawQueue.push({level, message});
        }
        else
        {
          data.queue.push(std::move(output));
        }
      }
      data.cv.notify_one();
    }
    else
    {
      std::lock_guard<std::mutex> lock(data.mutex);

      if (data.useExternalHandler && data.externalHandler)
      {
        data.externalHandler(level, output, message);
      }
      else
      {
        rotateLogFileIfNeeded();

        if (data.fileStream)
        {
          (*data.fileStream) << output;
          data.fileStream->flush();
        }
        else
        {
          std::cout << output;
        }
      }
    }
  }

public:
  friend class LoggerStream;

  /// \brief Token type for pre-compiled format segments
  enum class FormatToken
  {
    Literal,    ///< Literal string segment
    Timestamp,  ///< %T - timestamp
    ThreadId,   ///< %t - thread ID
    Level,      ///< %L - log level
    Message     ///< %m - message content
  };

  /// \brief Pre-compiled format segment
  struct FormatSegment
  {
    FormatToken token;
    std::string literal;  ///< Only used when token == Literal
  };

  struct LoggerData
  {
    std::mutex mutex;
    std::condition_variable cv;
    std::queue<std::string> queue;
    std::queue<std::pair<Level, std::string>> rawQueue; // For external handlers
    std::thread workerThread;
    std::atomic<bool> exit{false};
    bool asyncMode = false;
    Level minLevel = Level::Info;
    std::unique_ptr<std::ofstream> fileStream;
    std::string logBasePath;
    std::string currentLogDate;
    int retentionDays = 7;
    std::string timestampFormat = "%Y-%m-%d %H:%M:%S";
    ExternalHandler externalHandler;
    bool useExternalHandler = false;
    /// Original log format string (for getLogFormat())
    std::string _logFormat = "[%T] [%L] %m";
    /// Pre-compiled format segments for fast formatting
    std::vector<FormatSegment> _compiledFormat;

    ~LoggerData()
    {
      // Ensure clean shutdown during static destruction
      try
      {
        exit = true;
        cv.notify_all();
        if (workerThread.joinable())
        {
          workerThread.join();
        }
      }
      catch (...)
      {
        // Ignore exceptions during static destruction
      }
    }
  };

  static LoggerData &getData()
  {
    static LoggerData data;
    return data;
  }

  static void runWorker()
  {
    auto &data = getData();
    while (true)
    {
      std::unique_lock<std::mutex> lock(data.mutex);
      data.cv.wait(lock,
                   [&data] { return !data.queue.empty() || !data.rawQueue.empty() || data.exit; });

      // Process external handler queue
      while (!data.rawQueue.empty() && data.useExternalHandler && data.externalHandler)
      {
        auto [level, rawMessage] = data.rawQueue.front();
        data.rawQueue.pop();

        // Format the message for external handler
        std::string formattedMessage = formatLogMessage(level, rawMessage);

        // Temporarily unlock to call external handler
        lock.unlock();
        data.externalHandler(level, formattedMessage, rawMessage);
        lock.lock();
      }

      // Process normal logging queue
      while (!data.queue.empty())
      {
        rotateLogFileIfNeeded();
        const std::string &entry = data.queue.front();

        if (data.fileStream)
        {
          (*data.fileStream) << entry;
          data.fileStream->flush();
        }
        else
        {
          std::cout << entry;
        }
        data.queue.pop();
      }

      if (data.exit)
      {
        break;
      }
    }
  }

  static std::string timestamp()
  {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    auto &data = getData();
    oss << std::put_time(std::localtime(&t), data.timestampFormat.c_str());
    if (data.timestampFormat.find("%S") != std::string::npos)
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
    auto &data = getData();
    if (data.logBasePath.empty() || data.useExternalHandler)
    {
      // No log file path specified or external handler is active, skip file logging
      return;
    }

    namespace fs = std::filesystem;
    auto logPath = fs::path(data.logBasePath);
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
        std::cerr << "[Logger] Failed to create log directory: " << logDir << " - " << ec.message()
                  << std::endl;
        return;
      }
    }

    std::string today = currentDate();
    if (today != data.currentLogDate)
    {
      data.currentLogDate = today;
      std::string rotatedPath =
        (logDir / (logPath.filename().string() + "." + data.currentLogDate + ".log")).string();

      data.fileStream = std::make_unique<std::ofstream>(rotatedPath, std::ios::app);
      if (!data.fileStream->is_open())
      {
        std::cerr << "[Logger] Failed to open rotated log file: " << rotatedPath << std::endl;
        data.fileStream.reset();
      }

      deleteOldLogFiles();
    }
  }

  static void deleteOldLogFiles()
  {
    auto &data = getData();
    if (data.logBasePath.empty() || data.retentionDays <= 0)
    {
      return;
    }

    namespace fs = std::filesystem;
    auto now = std::chrono::system_clock::now();
    auto logPath = fs::path(data.logBasePath);
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

    for (const auto &entry : fs::directory_iterator(logDir, dir_ec))
    {
      if (dir_ec)
      {
        std::cerr << "[Logger] Failed to iterate log directory: " << logDir << " - "
                  << dir_ec.message() << std::endl;
        break;
      }
      const auto &path = entry.path();
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
      auto fileTime = std::chrono::system_clock::from_time_t(std::mktime(&tm));
      // Only compare date, not time-of-day
      auto fileDays = std::chrono::duration_cast<std::chrono::hours>(now - fileTime).count() / 24;
      if (fileDays >= data.retentionDays)
      {
        std::error_code ec;
        fs::remove(path, ec);
        if (ec)
        {
          std::cerr << "[Logger] Failed to delete old log file: " << path << " - " << ec.message()
                    << std::endl;
        }
      }
    }
  }

  static const char *levelToString(Level level)
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

  /// \brief Compile a format string into segments for fast formatting
  /// \param format The format string to compile
  /// \param segments Output vector to store compiled segments
  static void compileFormat(const std::string &format, std::vector<FormatSegment> &segments)
  {
    segments.clear();
    std::string currentLiteral;

    for (std::size_t i = 0; i < format.size(); ++i)
    {
      if (format[i] == '%' && i + 1 < format.size())
      {
        // Flush accumulated literal before processing placeholder
        if (!currentLiteral.empty())
        {
          segments.push_back({FormatToken::Literal, std::move(currentLiteral)});
          currentLiteral.clear();
        }

        char spec = format[i + 1];
        switch (spec)
        {
        case 'T':
          segments.push_back({FormatToken::Timestamp, ""});
          ++i;
          break;
        case 't':
          segments.push_back({FormatToken::ThreadId, ""});
          ++i;
          break;
        case 'L':
          segments.push_back({FormatToken::Level, ""});
          ++i;
          break;
        case 'm':
          segments.push_back({FormatToken::Message, ""});
          ++i;
          break;
        case '%':
          currentLiteral += '%';
          ++i;
          break;
        default:
          // Unknown placeholder, treat % as literal
          currentLiteral += format[i];
          break;
        }
      }
      else
      {
        currentLiteral += format[i];
      }
    }

    // Flush any remaining literal
    if (!currentLiteral.empty())
    {
      segments.push_back({FormatToken::Literal, std::move(currentLiteral)});
    }
  }

  /// \brief Format string using printf-style format and varargs
  /// \param level The log level
  /// \param fmt Printf-style format string
  /// \param args Variable arguments list
  /// \note Thread-safe, handles buffer allocation automatically
  static void logFormatted(Level level, const char *fmt, va_list args)
  {
    auto &data = getData();
    if (level < data.minLevel)
    {
      return;
    }

    // Determine required buffer size
    va_list argsCopy;
    va_copy(argsCopy, args);
    int size = std::vsnprintf(nullptr, 0, fmt, argsCopy);
    va_end(argsCopy);

    if (size < 0)
    {
      // Format error, log error message instead
      log(level, "[Logger] Invalid format string");
      return;
    }

    // Allocate buffer and format string
    std::vector<char> buffer(size + 1);
    std::vsnprintf(buffer.data(), buffer.size(), fmt, args);

    // Log formatted message
    log(level, std::string(buffer.data(), size));
  }

  /// \brief Format a log message using pre-compiled format segments
  /// \param level The log level
  /// \param message The raw message content
  /// \return Formatted log string with newline
  /// \note Uses pre-compiled segments for optimal performance.
  ///       Thread-safe: all shared data is copied under lock before formatting.
  static std::string formatLogMessage(Level level, const std::string &message)
  {
    auto &data = getData();

    // Copy compiled segments and timestamp format under lock to avoid race conditions
    std::vector<FormatSegment> segments;
    std::string timestampFmt;
    {
      std::lock_guard<std::mutex> lock(data.mutex);
      // Compile on first use if not yet compiled
      if (data._compiledFormat.empty() && !data._logFormat.empty())
      {
        compileFormat(data._logFormat, data._compiledFormat);
      }
      segments = data._compiledFormat;
      timestampFmt = data.timestampFormat;
    }

    std::ostringstream oss;
    for (const auto &seg : segments)
    {
      switch (seg.token)
      {
      case FormatToken::Literal:
        oss << seg.literal;
        break;
      case FormatToken::Timestamp:
        {
          // Generate timestamp using copied format (thread-safe)
          auto now = std::chrono::system_clock::now();
          auto t = std::chrono::system_clock::to_time_t(now);
          auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
          oss << std::put_time(std::localtime(&t), timestampFmt.c_str());
          if (timestampFmt.find("%S") != std::string::npos)
          {
            oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
          }
        }
        break;
      case FormatToken::ThreadId:
        oss << std::this_thread::get_id();
        break;
      case FormatToken::Level:
        oss << levelToString(level);
        break;
      case FormatToken::Message:
        oss << message;
        break;
      }
    }
    oss << std::endl;
    return oss.str();
  }
};

/// \brief Stream interface for composing and emitting log messages with
/// levels.
class LoggerStream
{
public:
  explicit LoggerStream(Logger::Level level) : _level(level), _flushed(false) {}

  template <typename T> LoggerStream &operator<<(const T &value)
  {
    _stream << value;
    return *this;
  }

  LoggerStream &operator<<(Logger::Endl)
  {
    flush();
    return *this;
  }

  ~LoggerStream()
  {
    try
    {
      if (!_flushed && !_stream.str().empty())
      {
        flush();
      }
    }
    catch (...)
    {
      // Ignore all exceptions in destructor to prevent double-exception
      // issues
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
    iora::core::Logger::flush();
  }
};

/// \brief Proxy for streaming log messages at specific log levels.
class LoggerProxy
{
public:
  LoggerStream operator<<(Logger::Level level) { return Logger::stream(level); }
};

inline LoggerProxy Logger;

namespace detail
{
  /// \brief Extract filename from full path at compile-time
  /// Handles both Unix (/) and Windows (\) path separators
  constexpr const char* basename(const char* path)
  {
    const char* file = path;
    while (*path)
    {
      if (*path == '/' || *path == '\\')
      {
        file = path + 1;
      }
      ++path;
    }
    return file;
  }
} // namespace detail

#define IORA_LOG_CONTEXT_PREFIX "[" << iora::core::detail::basename(__FILE__) << ":" << __LINE__ << " " << __func__ << "] "

#define IORA_LOG_WITH_LEVEL(level, msg)                                                            \
  do                                                                                               \
  {                                                                                                \
    iora::core::Logger << iora::core::Logger::Level::level << IORA_LOG_CONTEXT_PREFIX << msg       \
                       << iora::core::Logger::endl;                                                \
  } while (0)

#define IORA_LOG_TRACE(msg) IORA_LOG_WITH_LEVEL(Trace, msg)
#define IORA_LOG_DEBUG(msg) IORA_LOG_WITH_LEVEL(Debug, msg)
#define IORA_LOG_INFO(msg) IORA_LOG_WITH_LEVEL(Info, msg)
#define IORA_LOG_WARN(msg) IORA_LOG_WITH_LEVEL(Warning, msg)
#define IORA_LOG_ERROR(msg) IORA_LOG_WITH_LEVEL(Error, msg)
#define IORA_LOG_FATAL(msg) IORA_LOG_WITH_LEVEL(Fatal, msg)

/// \brief Printf-style logging macros with context information
/// These macros include file:line:function context via IORA_LOG_CONTEXT_PREFIX.
/// \warning Messages are limited to 4096 bytes (including null terminator).
///          Longer messages will be silently truncated by std::snprintf.
///          For messages exceeding this limit, use Logger::tracef() directly
///          or consider using stream-style logging (IORA_LOG_TRACE).
/// \note Uses stack buffer for performance - suitable for most logging scenarios.
#define IORA_LOG_TRACEF(fmt, ...)                                                                      \
  do                                                                                                   \
  {                                                                                                    \
    std::ostringstream _oss;                                                                           \
    _oss << IORA_LOG_CONTEXT_PREFIX;                                                                   \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::trace(_oss.str() + _buf);                                                      \
  } while (0)

#define IORA_LOG_DEBUGF(fmt, ...)                                                                      \
  do                                                                                                   \
  {                                                                                                    \
    std::ostringstream _oss;                                                                           \
    _oss << IORA_LOG_CONTEXT_PREFIX;                                                                   \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::debug(_oss.str() + _buf);                                                      \
  } while (0)

#define IORA_LOG_INFOF(fmt, ...)                                                                       \
  do                                                                                                   \
  {                                                                                                    \
    std::ostringstream _oss;                                                                           \
    _oss << IORA_LOG_CONTEXT_PREFIX;                                                                   \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::info(_oss.str() + _buf);                                                       \
  } while (0)

#define IORA_LOG_WARNF(fmt, ...)                                                                       \
  do                                                                                                   \
  {                                                                                                    \
    std::ostringstream _oss;                                                                           \
    _oss << IORA_LOG_CONTEXT_PREFIX;                                                                   \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::warning(_oss.str() + _buf);                                                    \
  } while (0)

#define IORA_LOG_ERRORF(fmt, ...)                                                                      \
  do                                                                                                   \
  {                                                                                                    \
    std::ostringstream _oss;                                                                           \
    _oss << IORA_LOG_CONTEXT_PREFIX;                                                                   \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::error(_oss.str() + _buf);                                                      \
  } while (0)

#define IORA_LOG_FATALF(fmt, ...)                                                                      \
  do                                                                                                   \
  {                                                                                                    \
    std::ostringstream _oss;                                                                           \
    _oss << IORA_LOG_CONTEXT_PREFIX;                                                                   \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::fatal(_oss.str() + _buf);                                                      \
  } while (0)

inline LoggerStream Logger::stream(Logger::Level level) { return LoggerStream(level); }
} // namespace core
} // namespace iora