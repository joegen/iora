#pragma once

#include <iostream>
#include <string>
#include <mutex>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <memory>

namespace iora {
// Namespace log
namespace core {

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
      auto& data = getData();
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
      auto& data = getData();
      std::unique_lock<std::mutex> lock(data.mutex);
      // Always flush queue for both sync and async modes
      while (!data.queue.empty())
      {
        rotateLogFileIfNeeded();
        const std::string& entry = data.queue.front();
        std::cout << entry;
        if (data.fileStream)
        {
          (*data.fileStream) << entry;
          data.fileStream->flush();
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
      auto& data = getData();
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
      auto& data = getData();
      std::lock_guard<std::mutex> lock(data.mutex);
      data.minLevel = level;
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
      auto& data = getData();
      if (level < data.minLevel)
      {
        return;
      }

      std::ostringstream oss;
      oss << "[" << timestamp() << "] "
          << "[" << levelToString(level) << "] " << message << std::endl;

      std::string output = oss.str();

      if (data.asyncMode)
      {
        {
          std::lock_guard<std::mutex> lock(data.mutex);
          data.queue.push(std::move(output));
        }
        data.cv.notify_one();
      }
      else
      {
        std::lock_guard<std::mutex> lock(data.mutex);
        rotateLogFileIfNeeded();
        std::cout << output;
        if (data.fileStream)
        {
          (*data.fileStream) << output;
          data.fileStream->flush();
        }
      }
    }

  public:
    friend class LoggerStream;

    struct LoggerData
    {
      std::mutex mutex;
      std::condition_variable cv;
      std::queue<std::string> queue;
      std::thread workerThread;
      std::atomic<bool> exit{false};
      bool asyncMode = false;
      Level minLevel = Level::Info;
      std::unique_ptr<std::ofstream> fileStream;
      std::string logBasePath;
      std::string currentLogDate;
      int retentionDays = 7;
      std::string timestampFormat = "%Y-%m-%d %H:%M:%S";

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

    static LoggerData& getData()
    {
      static LoggerData data;
      return data;
    }

    static void runWorker()
    {
      auto& data = getData();
      while (true)
      {
        std::unique_lock<std::mutex> lock(data.mutex);
        data.cv.wait(lock,
                     [&data] { return !data.queue.empty() || data.exit; });

        while (!data.queue.empty())
        {
          rotateLogFileIfNeeded();
          const std::string& entry = data.queue.front();
          std::cout << entry;
          if (data.fileStream)
          {
            (*data.fileStream) << entry;
            data.fileStream->flush();
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
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()) %
                1000;

      std::ostringstream oss;
      auto& data = getData();
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
      auto& data = getData();
      if (data.logBasePath.empty())
      {
        // No log file path specified, skip file logging
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
          std::cerr << "[Logger] Failed to create log directory: " << logDir
                    << " - " << ec.message() << std::endl;
          return;
        }
      }

      std::string today = currentDate();
      if (today != data.currentLogDate)
      {
        data.currentLogDate = today;
        std::string rotatedPath = (logDir / (logPath.filename().string() + "." +
                                             data.currentLogDate + ".log"))
                                      .string();

        data.fileStream =
            std::make_unique<std::ofstream>(rotatedPath, std::ios::app);
        if (!data.fileStream->is_open())
        {
          std::cerr << "[Logger] Failed to open rotated log file: "
                    << rotatedPath << std::endl;
          data.fileStream.reset();
        }

        deleteOldLogFiles();
      }
    }

    static void deleteOldLogFiles()
    {
      auto& data = getData();
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
        if (fileDays >= data.retentionDays)
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
    iora::core::Logger << iora::core::Logger::Level::level << LOG_CONTEXT_PREFIX \
                      << msg << iora::core::Logger::endl;                       \
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
} } // namespace iora::core