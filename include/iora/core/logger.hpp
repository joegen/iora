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
#include <cstdlib>
#include <cstring>
#include <ctime>
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

#ifdef _WIN32
  #include <io.h>
  #define isatty _isatty
  #define fileno _fileno
#else
  #include <unistd.h>
#endif

namespace iora
{
namespace core
{
namespace detail
{
  /// \brief Thread-safe reentrant local time conversion.
  /// On POSIX uses localtime_r; on Windows uses localtime_s.
  /// Returns true on success and fills tmBuf; returns false on failure.
  inline bool localTimeReentrant(const std::time_t *t, std::tm *tmBuf)
  {
#ifdef _WIN32
    return ::localtime_s(tmBuf, t) == 0;
#else
    return ::localtime_r(t, tmBuf) != nullptr;
#endif
  }

  /// \brief Thread-safe UTC time conversion (no TZ global mutation).
  /// Replaces std::mktime when TZ-globals contention is undesirable.
  /// On POSIX uses timegm; on Windows uses _mkgmtime.
  inline std::time_t timeGmReentrant(std::tm *tmBuf)
  {
#ifdef _WIN32
    return ::_mkgmtime(tmBuf);
#else
    return ::timegm(tmBuf);
#endif
  }
} // namespace detail
} // namespace core
} // namespace iora

namespace iora
{
// Namespace log
namespace core
{

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

// Source-location capture for the direct level functions
// (trace/debug/info/warning/error/fatal). __builtin_FILE/__builtin_LINE/
// __builtin_FUNCTION evaluate at the CALL SITE when used as default-argument
// values — the C++17-compatible backport of C++20 std::source_location.
// Guard carefully: __has_builtin was only added in GCC 10, but these builtins
// have existed since GCC 4.8, so a naive
// `defined(__has_builtin) && __has_builtin(__builtin_FILE)` guard would wrongly
// disable capture on GCC 7/8/9. Probe all three builtins (MSVC >= 16.6 also
// provides them via __has_builtin).
#if defined(__has_builtin)
  #if __has_builtin(__builtin_FILE) && __has_builtin(__builtin_LINE) &&        \
    __has_builtin(__builtin_FUNCTION)
    #define IORA_HAS_SRC_LOC 1
  #endif
#elif defined(__GNUC__)
  // GCC < 10 lacks __has_builtin but has had these builtins since 4.8. A
  // non-GCC compiler defining __GNUC__ in compat mode yet predating the
  // builtins is outside iora's GCC/Clang Linux CI (modern Intel icx is
  // Clang-based and takes the __has_builtin branch above).
  #define IORA_HAS_SRC_LOC 1
#endif

#if defined(IORA_HAS_SRC_LOC)
  #define IORA_SRC_FILE __builtin_FILE()
  #define IORA_SRC_LINE __builtin_LINE()
  #define IORA_SRC_FUNC __builtin_FUNCTION()
#else
  #define IORA_SRC_FILE ""
  #define IORA_SRC_LINE 0
  #define IORA_SRC_FUNC ""
#endif

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

    data.minLevel.store(level, std::memory_order_relaxed);
    data.asyncMode.store(async, std::memory_order_relaxed);
    data.exit = false;
    // If no filePath provided, log to console only (no file)
    data.logBasePath = filePath;
    data.retentionDays = retentionDays;
    data.timestampFormat = timeFormat;
    // Reset current log date so rotateLogFileIfNeeded always opens a new file
    data.currentLogDate.clear();

    // Clear any leftover queued messages from a prior session to prevent
    // cross-session leaks (e.g., rawQueue entries left after shutdown when
    // useExternalHandler was already cleared).
    while (!data.queue.empty()) data.queue.pop();
    while (!data.rawQueue.empty()) data.rawQueue.pop();

    rotateLogFileIfNeeded();

    if (data.asyncMode.load(std::memory_order_relaxed) && !data.workerThread.joinable())
    {
      data.workerThread = std::thread(runWorker);
    }
  }

  static void flush()
  {
    auto &data = getData();
    std::unique_lock<std::mutex> lock(data.mutex);

    // Flush external handler queue first. Gated on handlerReentryDepth()==0 (like
    // logDispatch): a handler that itself calls flush() — e.g. via
    // LoggerStream::flush() when it logs through the stream proxy — must NOT
    // re-invoke the handler on the already-queued entries (that is unbounded
    // recursion, O(backlog) stack frames). At depth > 0 the entries are left for
    // the outer flush()/worker running at depth 0.
    while (!data.rawQueue.empty() && data.useExternalHandler && data.externalHandler &&
           handlerReentryDepth() == 0)
    {
      auto [level, rawMessage] = data.rawQueue.front();
      data.rawQueue.pop();

      // Capture everything needed BEFORE unlocking — a tear-out
      // (clear/setExternalHandler) can null the gate fields once the lock is
      // released. The gate-check (loop condition), handler copy, and the
      // in-flight increment inside runHandlerUnlocked form one indivisible
      // critical section under the still-held lock.
      auto segments = data._compiledFormat;
      auto timestampFmt = data.timestampFormat;
      auto handler = data.externalHandler;

      // Drains/rethrows to the synchronous flush() caller (already re-locked).
      runHandlerUnlocked(lock, data,
        [&] { formatAndInvokeRawHandler(level, rawMessage, segments, timestampFmt, handler); });
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
    auto &data = getData();
    // A throwing sink during the final drain must not prevent shutdown from
    // setting exit and joining the worker (the worker's own drain already
    // swallows sink exceptions); otherwise a throwing handler could leave the
    // worker running until static destruction. Swallow-and-continue here too.
    try
    {
      flush();
    }
    catch (const std::exception &ex)
    {
      std::cerr << "Logger: external handler threw during shutdown flush: " << ex.what()
                << std::endl;
    }
    catch (...)
    {
      std::cerr << "Logger: external handler threw a non-std exception during shutdown flush"
                << std::endl;
    }
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
    data.minLevel.store(level, std::memory_order_relaxed);
  }

  /// \brief Get the current minimum log level
  /// \return The current minimum log level
  static Level getLevel()
  {
    auto &data = getData();
    // minLevel is atomic; no lock needed (matches the lock-free log() gate).
    return data.minLevel.load(std::memory_order_relaxed);
  }

  /// \brief Register an external log handler
  /// When an external handler is registered, file logging and console output are disabled
  /// \param handler The external handler function to register
  static void setExternalHandler(ExternalHandler handler)
  {
    auto &data = getData();
    std::unique_lock<std::mutex> lock(data.mutex);

    // Drain any in-flight invocation of a PREVIOUS handler before swapping it
    // out — the same tear-out UAF as clearExternalHandler. Null both gate fields
    // first (no new invocation starts), then wait (self-call -> inflight==1,
    // else inflight==0). Messages logged during this swap window take the normal
    // queue/file path and are not delivered to either handler (accepted).
    data.externalHandler = nullptr;
    data.useExternalHandler = false;
    // Self-call detection via the calling thread's handler-reentry depth. Each
    // handler invocation pairs ++externalHandlerInflight with ++depth, so this
    // thread OWNS exactly `depth` of the in-flight count (all pinned on its own
    // stack and unable to drain while it waits). Drain to `depth` — waiting out
    // every OTHER thread's invocation without waiting on our own. (target 0 when
    // not inside a handler; a hard-coded 1 would deadlock at nested depth >= 2.)
    const int target = handlerReentryDepth();
    data.externalHandlerDone.wait(lock, [&] { return data.externalHandlerInflight == target; });

    // Discard any entries still queued for the PREVIOUS handler. Rerouting them to
    // the normal sink would print to cout while the NEW handler is active (which
    // disables console/file output), and delivering them to the new handler would
    // be misdelivery — so, consistent with the swap-window "not delivered to either
    // handler" semantics above, they are dropped. Emptying rawQueue here also
    // prevents the orphaned-queue busy-spin (an alternative to the predicate gate).
    while (!data.rawQueue.empty())
    {
      data.rawQueue.pop();
    }

    // Close file stream AFTER the drain (so a racing normal-queue drain never
    // wrote to a half-torn ofstream), then install the new handler.
    if (data.fileStream && data.fileStream->is_open())
    {
      data.fileStream->close();
      data.fileStream.reset();
    }

    data.externalHandler = std::move(handler);
    data.useExternalHandler = true;
  }

  /// \brief Remove external log handler and restore normal logging
  static void clearExternalHandler()
  {
    auto &data = getData();
    std::unique_lock<std::mutex> lock(data.mutex);
    // Null both gate fields together so no NEW invocation can start (runWorker
    // and flush() gate on them under the lock), then drain any in-flight
    // invocation before returning — so a [this]-capturing handler's object can
    // never be destroyed mid-call.
    data.externalHandler = nullptr;
    data.useExternalHandler = false;
    // A handler re-entering to clear itself owns `depth` of the in-flight count
    // (each invocation pairs ++inflight with ++depth), all pinned on its own stack
    // and unable to drain while it waits, so drain to `depth` — the OTHERS, not its
    // own nested invocations. Covers the sync log(), flush(), and async-worker
    // paths. Never an unconditional skip: a concurrent flush()/log() may be
    // invoking the same captured object on another thread. (A hard-coded 1 would
    // deadlock at nested depth >= 2.)
    const int target = handlerReentryDepth();
    data.externalHandlerDone.wait(lock, [&] { return data.externalHandlerInflight == target; });

    // Reroute any entries still queued for the removed handler so they are not
    // orphaned in rawQueue (which would busy-spin the worker) and not lost — they
    // land on the normal queue for file/console.
    rerouteRawQueueToNormalQueueLocked(data);
    data.cv.notify_one(); // wake the worker to drain the rerouted normal-queue entries
    // File logging will be restored on next log call via rotateLogFileIfNeeded
  }

  /// \brief Set the log format string (thread-safe)
  /// Supported placeholders:
  ///   %T - timestamp (uses timestampFormat from init())
  ///   %t - thread ID (hex hash: 8 digits on 32-bit, 16 digits on 64-bit)
  ///   %L - log level (e.g., INFO, DEBUG, ERROR)
  ///   %m - message content
  ///   %F - source file name (only filename, no directory path)
  ///   %l - source line number
  ///   %f - function name
  ///   %% - literal percent sign
  /// \param format The format string (default: "[%T] [%L] %m")
  /// Example with thread ID: "[%T] [%t] [%L] %m"
  /// Example with source location: "[%T] [%L] [%F:%l %f] %m"
  /// \note Format is pre-compiled for performance; parsing happens only on this call.
  /// \note Empty format strings are ignored.
  /// \note Thread ID is formatted as hex hash with platform-specific width for consistency.
  /// \note The direct level functions (trace/debug/info/warning/error/fatal)
  ///       capture source location implicitly, so %F/%l/%f render for them
  ///       without a macro. The printf-style *f family and the LoggerStream /
  ///       Logger<<Level proxy path still require the IORA_LOG_* macros for
  ///       source location placeholders (%F, %l, %f).
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

  /// \brief Enable or disable ANSI color codes for console output
  /// \param enable Whether to enable console colors
  /// \note Colors are only applied to console output (std::cout), not file logs
  /// \note Automatically checks if stdout is a TTY and respects NO_COLOR environment variable
  /// \note Color scheme: TRACE=gray, DEBUG=cyan, INFO=green, WARN=yellow, ERROR=red, FATAL=bright red
  static void setConsoleColors(bool enable)
  {
    auto &data = getData();
    std::lock_guard<std::mutex> lock(data.mutex);

    // Check NO_COLOR environment variable (standard convention)
    const char *noColor = std::getenv("NO_COLOR");
    if (noColor && noColor[0] != '\0')
    {
      // NO_COLOR is set and non-empty, disable colors
      data._enableConsoleColors = false;
      data._isTTY = false;
      return;
    }

    // Check if stdout is a TTY
    data._isTTY = (isatty(fileno(stdout)) != 0);

    // Only enable colors if requested, stdout is a TTY, and NO_COLOR not set
    data._enableConsoleColors = enable && data._isTTY;
  }

  /// \brief Direct level-logging functions.
  /// These capture the caller's source location implicitly via defaulted
  /// compiler-builtin arguments (IORA_SRC_FILE/LINE/FUNC), so the %F/%l/%f
  /// format placeholders render without needing an IORA_LOG_* macro at the
  /// call site. On a compiler lacking the builtins the location falls back to
  /// empty file, line 0, empty function.
  /// \note Source location reaches a synchronous external handler's
  /// formattedMessage argument, but not an async handler (which re-formats
  /// from the raw {level, message} queue and therefore renders blank location).
  static void trace(const std::string &message, const char *file = IORA_SRC_FILE,
                    int line = IORA_SRC_LINE, const char *function = IORA_SRC_FUNC)
  {
    log(Level::Trace, message, file, line, function);
  }
  static void debug(const std::string &message, const char *file = IORA_SRC_FILE,
                    int line = IORA_SRC_LINE, const char *function = IORA_SRC_FUNC)
  {
    log(Level::Debug, message, file, line, function);
  }
  static void info(const std::string &message, const char *file = IORA_SRC_FILE,
                   int line = IORA_SRC_LINE, const char *function = IORA_SRC_FUNC)
  {
    log(Level::Info, message, file, line, function);
  }
  static void warning(const std::string &message, const char *file = IORA_SRC_FILE,
                      int line = IORA_SRC_LINE, const char *function = IORA_SRC_FUNC)
  {
    log(Level::Warning, message, file, line, function);
  }
  static void error(const std::string &message, const char *file = IORA_SRC_FILE,
                    int line = IORA_SRC_LINE, const char *function = IORA_SRC_FUNC)
  {
    log(Level::Error, message, file, line, function);
  }
  static void fatal(const std::string &message, const char *file = IORA_SRC_FILE,
                    int line = IORA_SRC_LINE, const char *function = IORA_SRC_FUNC)
  {
    log(Level::Fatal, message, file, line, function);
  }

// These are implementation detail of the six default arguments above and are not
// part of the public API — undefine them so they do not leak into downstream TUs
// that include this header. Nothing consumes IORA_HAS_SRC_LOC either, so it is
// undefined too rather than left as macro-namespace surface.
#undef IORA_SRC_FILE
#undef IORA_SRC_LINE
#undef IORA_SRC_FUNC
#undef IORA_HAS_SRC_LOC

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
    if (level < data.minLevel.load(std::memory_order_relaxed))
    {
      return;
    }
    logDispatch(data, level, message, formatLogMessage(level, message));
  }

  /// \brief Log a message with source location information
  /// \param level The log level
  /// \param message The message to log
  /// \param file Source file name (from __FILE__)
  /// \param line Source line number (from __LINE__)
  /// \param function Function name (from __func__)
  static void log(Level level, const std::string &message,
                  const char *file, int line, const char *function)
  {
    auto &data = getData();
    if (level < data.minLevel.load(std::memory_order_relaxed))
    {
      return;
    }
    logDispatch(data, level, message, formatLogMessage(level, message, file, line, function));
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
    Message,    ///< %m - message content
    File,       ///< %F - source file name
    Line,       ///< %l - source line number
    Function    ///< %f - function name
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
    // atomic: read on the hot log() gate/branch without holding `mutex`; written
    // in init()/setLevel(). Plain scalars here were a data race. relaxed ordering
    // is sufficient — neither flag publishes non-atomic data (the queue/handler
    // handoff is carried by `mutex`), so no cross-atomic ordering is required.
    std::atomic<bool> asyncMode{false};
    std::atomic<Level> minLevel{Level::Info};
    std::unique_ptr<std::ofstream> fileStream;
    std::string logBasePath;
    std::string currentLogDate;
    int retentionDays = 7;
    std::string timestampFormat = "%Y-%m-%d %H:%M:%S";
    ExternalHandler externalHandler;
    bool useExternalHandler = false;
    /// In-flight count of external-handler invocations currently executing in
    /// their unlocked window (runWorker + any concurrent flush()). Plain int,
    /// mutated and read ONLY under `mutex` (the mutex supplies happens-before).
    /// clear/setExternalHandler drain on this before tearing out the handler so a
    /// [this]-capturing handler's object cannot be destroyed mid-invocation.
    int externalHandlerInflight = 0;
    /// Signalled (notify_all) on every decrement of externalHandlerInflight.
    /// Dedicated CV (not `cv`) so drain-waiters never consume worker wakeups.
    std::condition_variable externalHandlerDone;
    /// Original log format string (for getLogFormat())
    std::string _logFormat = "[%T] [%L] %m";
    /// Pre-compiled format segments for fast formatting
    std::vector<FormatSegment> _compiledFormat;
    /// Enable ANSI color codes for console output
    bool _enableConsoleColors = false;
    /// Cache whether stdout is a TTY
    bool _isTTY = false;

    ~LoggerData()
    {
      // Ensure clean shutdown during static destruction
      try
      {
        // Set the predicate UNDER the mutex (as shutdown() does): mutating a CV
        // predicate without the wait mutex — even an atomic one — can lose the
        // wakeup if the worker is between its predicate check and parking,
        // hanging join() at teardown.
        {
          std::lock_guard<std::mutex> lock(mutex);
          exit = true;
        }
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

#if defined(IORA_CORE_SHARED) || defined(IORA_CORE_BUILDING)
  static LoggerData &getData();
#else
  static LoggerData &getData()
  {
    static LoggerData data;
    return data;
  }
#endif

  /// \brief Per-thread external-handler reentrancy depth.
  /// A thread executing a user log handler in its unlocked window has depth > 0.
  /// clear/setExternalHandler read this to detect a self-call — a handler that
  /// re-enters to swap or clear the handler — and drain to inflight == 1 (its own
  /// invocation) instead of hanging. Replaces the former workerThreadId
  /// self-detection, which could go stale once the worker was joined (a later
  /// thread reusing that OS id would misfire) and never covered handler
  /// invocations on the sync log() path or the flush() thread at all.
  static int &handlerReentryDepth()
  {
    static thread_local int depth = 0;
    return depth;
  }

  /// \brief RAII marker: the current thread is executing an external handler for
  /// the duration of the (unlocked) callback, so a self-call into
  /// clear/setExternalHandler is detected. Exception-safe.
  struct HandlerInvocationScope
  {
    HandlerInvocationScope() { ++handlerReentryDepth(); }
    ~HandlerInvocationScope() { --handlerReentryDepth(); }
    HandlerInvocationScope(const HandlerInvocationScope &) = delete;
    HandlerInvocationScope &operator=(const HandlerInvocationScope &) = delete;
  };

  /// \brief Run an external-handler invocation outside `data.mutex` with
  /// inflight-drain bookkeeping. Precondition: `lock` is HELD and the gate-check
  /// + handler copy were already done under it. Increments the in-flight count
  /// (still locked), releases the lock, runs `invoke()`, then re-acquires the
  /// lock, decrements, and notifies drain-waiters. On exception it performs the
  /// same teardown and rethrows — and has ALREADY re-acquired the lock — so the
  /// caller (flush/log propagate; runWorker swallows+continues) must not re-lock.
  /// Never holds `mutex` across the callback; balances inflight on every path.
  /// \note If the re-acquire `lock.lock()` itself throws (std::system_error), the
  /// `--inflight` cannot run and a drain-waiter would hang — but a mutex whose
  /// lock() throws is an unrecoverable/terminal condition, so this is accepted
  /// (the same assumption every other lock site in this class already makes).
  template <typename Invoke>
  static void runHandlerUnlocked(std::unique_lock<std::mutex> &lock, LoggerData &data,
                                 Invoke &&invoke)
  {
    ++data.externalHandlerInflight;
    lock.unlock();
    try
    {
      invoke();
    }
    catch (...)
    {
      lock.lock();
      --data.externalHandlerInflight;
      data.externalHandlerDone.notify_all();
      throw;
    }
    lock.lock();
    --data.externalHandlerInflight;
    data.externalHandlerDone.notify_all();
  }

  /// \brief Re-format a raw-queue entry and invoke the external handler under a
  /// HandlerInvocationScope. Runs inside runHandlerUnlocked's unlocked window;
  /// shared verbatim by flush() and runWorker(). `handler` is the caller's
  /// on-stack copy, taken under the lock while the loop gate required
  /// externalHandler non-null, so it is guaranteed non-null here.
  static void formatAndInvokeRawHandler(Level level, const std::string &rawMessage,
                                        const std::vector<FormatSegment> &segments,
                                        const std::string &timestampFmt,
                                        const ExternalHandler &handler)
  {
    std::string formattedMessage =
      formatLogMessageInternal(level, rawMessage, segments, timestampFmt);
    HandlerInvocationScope inv;
    handler(level, formattedMessage, rawMessage);
  }

  /// \brief Reroute any entries still queued for a REMOVED external handler from
  /// rawQueue to the normal queue, formatted with the current compiled format.
  /// Called under `mutex` by clearExternalHandler AFTER the in-flight drain (after
  /// a clear there is no handler, so console/file output is restored — the correct
  /// sink for these). Prevents (a) message loss and (b) an ORPHANED non-empty
  /// rawQueue that would busy-spin the worker (its cv predicate stays satisfied
  /// while the drain loop is gated off by useExternalHandler==false). rawQueue is
  /// only ever populated in async mode, so this is a no-op in sync mode.
  /// (setExternalHandler DROPS its old backlog instead — see there.)
  static void rerouteRawQueueToNormalQueueLocked(LoggerData &data)
  {
    while (!data.rawQueue.empty())
    {
      auto [level, rawMessage] = data.rawQueue.front();
      data.rawQueue.pop();
      std::string formatted =
        formatLogMessageInternal(level, rawMessage, data._compiledFormat, data.timestampFormat);
      // Match logDispatch's colorization: colorize before queuing when writing to
      // a color-enabled console (the level is lost once queued as a plain string).
      if (!data.fileStream && data._enableConsoleColors)
      {
        data.queue.push(colorizeOutput(formatted, level));
      }
      else
      {
        data.queue.push(std::move(formatted));
      }
    }
  }

  /// \brief Post-format dispatch shared by both log() overloads: route a
  /// fully-formatted `output` (with the raw `message` for the handler/rawQueue)
  /// to the async queue, the external handler, or the file/console path.
  /// \note A re-entrant call from INSIDE an external handler (handlerReentryDepth
  /// > 0) is NOT routed back to the handler — sync re-invocation would recurse
  /// unboundedly (stack overflow) and async would refeed rawQueue (worker
  /// livelock); such a message takes the normal queue/file/console path instead.
  static void logDispatch(LoggerData &data, Level level, const std::string &message,
                          std::string output)
  {
    if (data.asyncMode.load(std::memory_order_relaxed))
    {
      {
        std::lock_guard<std::mutex> lock(data.mutex);
        if (data.useExternalHandler && data.externalHandler && handlerReentryDepth() == 0)
        {
          data.rawQueue.push({level, message});
        }
        else if (!data.fileStream && data._enableConsoleColors)
        {
          // Colorize before queuing (level is lost once queued).
          data.queue.push(colorizeOutput(output, level));
        }
        else
        {
          data.queue.push(std::move(output));
        }
      }
      data.cv.notify_one();
      return;
    }

    std::unique_lock<std::mutex> lock(data.mutex);
    if (data.useExternalHandler && data.externalHandler && handlerReentryDepth() == 0)
    {
      // Copy-then-invoke: never hold `mutex` across a user callback (a handler
      // that re-enters Logger would self-deadlock on the non-recursive mutex);
      // the inflight-drain lets a concurrent clear/setExternalHandler wait the
      // invocation out instead of tearing the captured object out mid-call.
      auto handler = data.externalHandler;
      runHandlerUnlocked(lock, data,
                         [&]
                         {
                           HandlerInvocationScope inv;
                           handler(level, output, message);
                         });
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
        std::cout << colorizeOutput(output, level);
      }
    }
  }

  static void runWorker()
  {
    auto &data = getData();
    while (true)
    {
      std::unique_lock<std::mutex> lock(data.mutex);
      // The rawQueue term is gated on useExternalHandler: an orphaned non-empty
      // rawQueue (handler cleared before drain) must not keep the predicate true
      // while the drain loop is disabled — that would busy-spin. clear/set reroute
      // such entries to the normal queue, so this is also defense-in-depth.
      data.cv.wait(lock,
                   [&data]
                   {
                     return !data.queue.empty() ||
                            (!data.rawQueue.empty() && data.useExternalHandler) || data.exit;
                   });

      // Process external handler queue. handlerReentryDepth()==0 is defensive and
      // consistent with flush()/logDispatch — the worker's loop condition is only
      // ever evaluated at depth 0 (between invocations), so it never wrongly stops
      // the drain, but it keeps every handler-dispatch site uniformly gated.
      while (!data.rawQueue.empty() && data.useExternalHandler && data.externalHandler &&
             handlerReentryDepth() == 0)
      {
        auto [level, rawMessage] = data.rawQueue.front();
        data.rawQueue.pop();

        // Capture everything needed BEFORE unlocking — clearExternalHandler()
        // can null data.externalHandler while the lock is released. The gate,
        // handler copy, and inflight increment (inside runHandlerUnlocked) form
        // one indivisible critical section under the still-held lock.
        auto segments = data._compiledFormat;
        auto timestampFmt = data.timestampFormat;
        auto handler = data.externalHandler;

        try
        {
          // On normal return AND on rethrow, runHandlerUnlocked has already
          // re-acquired the lock and decremented inflight — the catch clauses
          // must NOT re-lock; a throwing sink must not std::terminate the worker.
          runHandlerUnlocked(lock, data,
            [&] { formatAndInvokeRawHandler(level, rawMessage, segments, timestampFmt, handler); });
        }
        catch (const std::exception &ex)
        {
          std::cerr << "Logger: external handler threw: " << ex.what() << std::endl;
          continue;
        }
        catch (...)
        {
          std::cerr << "Logger: external handler threw a non-std exception" << std::endl;
          continue;
        }
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

    // Snapshot timestampFormat under lock to avoid a race with init()
    auto &data = getData();
    std::string fmt;
    {
      std::lock_guard<std::mutex> lock(data.mutex);
      fmt = data.timestampFormat;
    }

    struct tm tmBuf{};
    if (!detail::localTimeReentrant(&t, &tmBuf))
    {
      return "[invalid-time]";
    }
    std::ostringstream oss;
    oss << std::put_time(&tmBuf, fmt.c_str());
    if (fmt.find("%S") != std::string::npos)
    {
      oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    }
    return oss.str();
  }

  static std::string currentDate()
  {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    struct tm tmBuf{};
    if (!detail::localTimeReentrant(&t, &tmBuf))
    {
      return "0000-00-00";
    }
    std::ostringstream oss;
    oss << std::put_time(&tmBuf, "%Y-%m-%d");
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
      struct tm tm{};
      std::istringstream ss(datePart);
      ss >> std::get_time(&tm, "%Y-%m-%d");
      if (ss.fail())
      {
        continue;
      }
      // Use timegm (UTC, no TZ globals) instead of std::mktime to avoid
      // contention on glibc's tzset internals. Comparison is day-granular
      // (retentionDays >= 1), so the UTC-vs-local offset is irrelevant.
      std::time_t fileEpoch = detail::timeGmReentrant(&tm);
      if (fileEpoch == static_cast<std::time_t>(-1))
      {
        // Malformed date parsed via get_time (e.g., "2025-02-30"): skip.
        continue;
      }
      auto fileTime = std::chrono::system_clock::from_time_t(fileEpoch);
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

  /// \brief Get ANSI color code for log level
  /// \param level The log level
  /// \return ANSI color code string
  static const char *getColorCode(Level level)
  {
    switch (level)
    {
    case Level::Trace:
      return "\033[90m"; // Gray
    case Level::Debug:
      return "\033[36m"; // Cyan
    case Level::Info:
      return "\033[32m"; // Green
    case Level::Warning:
      return "\033[33m"; // Yellow
    case Level::Error:
      return "\033[31m"; // Red
    case Level::Fatal:
      return "\033[91m"; // Bright Red
    default:
      return "";
    }
  }

  /// \brief Get ANSI reset code
  /// \return ANSI reset code string
  static const char *getResetCode()
  {
    return "\033[0m";
  }

  /// \brief Get colorized level string if colors enabled
  /// \param level The log level
  /// \param useColors Whether to apply ANSI colors
  /// \return Level string with optional ANSI color codes
  static std::string getColorizedLevel(Level level, bool useColors)
  {
    if (useColors)
    {
      std::string result;
      result += getColorCode(level);
      result += levelToString(level);
      result += getResetCode();
      return result;
    }
    else
    {
      return levelToString(level);
    }
  }

  /// \brief Colorize formatted log output by replacing level strings with colored versions
  /// \param output The formatted log message
  /// \param level The log level
  /// \return Colorized output if colors enabled, otherwise original output
  static std::string colorizeOutput(const std::string &output, Level level)
  {
    auto &data = getData();
    if (!data._enableConsoleColors)
    {
      return output;
    }

    // Find and replace the level string with colorized version
    const char *levelStr = levelToString(level);
    std::string colorizedLevel = getColorizedLevel(level, true);

    std::string result = output;
    size_t pos = result.find(levelStr);
    if (pos != std::string::npos)
    {
      result.replace(pos, std::strlen(levelStr), colorizedLevel);
    }

    return result;
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
        case 'F':
          segments.push_back({FormatToken::File, ""});
          ++i;
          break;
        case 'l':
          segments.push_back({FormatToken::Line, ""});
          ++i;
          break;
        case 'f':
          segments.push_back({FormatToken::Function, ""});
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
    if (level < data.minLevel.load(std::memory_order_relaxed))
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

  /// \brief Internal helper to format log message without locking
  /// \param level The log level
  /// \param message The raw message content
  /// \param segments Pre-compiled format segments
  /// \param timestampFmt Timestamp format string
  /// \return Formatted log string with newline
  /// \note Caller must ensure thread-safety (no locking performed internally)
  static std::string formatLogMessageInternal(Level level, const std::string &message,
                                              const std::vector<FormatSegment> &segments,
                                              const std::string &timestampFmt)
  {
    // Pre-generate timestamp once to avoid redundant time syscalls
    std::string timestampStr;
    bool needsTimestamp = false;
    for (const auto &seg : segments)
    {
      if (seg.token == FormatToken::Timestamp)
      {
        needsTimestamp = true;
        break;
      }
    }

    if (needsTimestamp)
    {
      auto now = std::chrono::system_clock::now();
      auto t = std::chrono::system_clock::to_time_t(now);
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
      struct tm tmBuf{};
      if (!detail::localTimeReentrant(&t, &tmBuf))
      {
        timestampStr = "[invalid-time]";
      }
      else
      {
        std::ostringstream tsOss;
        tsOss << std::put_time(&tmBuf, timestampFmt.c_str());
        if (timestampFmt.find("%S") != std::string::npos)
        {
          tsOss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        }
        timestampStr = tsOss.str();
      }
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
        oss << timestampStr;
        break;
      case FormatToken::ThreadId:
        {
          // Convert thread ID to numeric hash for consistent formatting across platforms
          std::hash<std::thread::id> hasher;
          std::size_t threadHash = hasher(std::this_thread::get_id());
          // Format as hex with width matching size_t (8 chars on 32-bit, 16 chars on 64-bit)
          oss << std::hex << std::setfill('0') << std::setw(sizeof(std::size_t) * 2)
              << threadHash << std::dec;
        }
        break;
      case FormatToken::Level:
        oss << levelToString(level);
        break;
      case FormatToken::Message:
        oss << message;
        break;
      case FormatToken::File:
        // File placeholder - will be empty unless source location provided
        break;
      case FormatToken::Line:
        // Line placeholder - will be empty unless source location provided
        break;
      case FormatToken::Function:
        // Function placeholder - will be empty unless source location provided
        break;
      }
    }
    oss << std::endl;
    return oss.str();
  }

  /// \brief Internal helper to format log message with source location (no locking)
  /// \param level The log level
  /// \param message The raw message content
  /// \param file Source file name (from __FILE__)
  /// \param line Source line number (from __LINE__)
  /// \param function Function name (from __func__)
  /// \param segments Pre-compiled format segments
  /// \param timestampFmt Timestamp format string
  /// \return Formatted log string with newline
  /// \note Caller must ensure thread-safety (no locking performed internally)
  static std::string formatLogMessageInternal(Level level, const std::string &message,
                                              const char *file, int line, const char *function,
                                              const std::vector<FormatSegment> &segments,
                                              const std::string &timestampFmt)
  {
    // Pre-generate timestamp once
    std::string timestampStr;
    bool needsTimestamp = false;
    for (const auto &seg : segments)
    {
      if (seg.token == FormatToken::Timestamp)
      {
        needsTimestamp = true;
        break;
      }
    }

    if (needsTimestamp)
    {
      auto now = std::chrono::system_clock::now();
      auto t = std::chrono::system_clock::to_time_t(now);
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
      struct tm tmBuf{};
      if (!detail::localTimeReentrant(&t, &tmBuf))
      {
        timestampStr = "[invalid-time]";
      }
      else
      {
        std::ostringstream tsOss;
        tsOss << std::put_time(&tmBuf, timestampFmt.c_str());
        if (timestampFmt.find("%S") != std::string::npos)
        {
          tsOss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        }
        timestampStr = tsOss.str();
      }
    }

    // Extract filename from full path
    std::string filename = detail::basename(file);

    std::ostringstream oss;
    for (const auto &seg : segments)
    {
      switch (seg.token)
      {
      case FormatToken::Literal:
        oss << seg.literal;
        break;
      case FormatToken::Timestamp:
        oss << timestampStr;
        break;
      case FormatToken::ThreadId:
        {
          std::hash<std::thread::id> hasher;
          std::size_t threadHash = hasher(std::this_thread::get_id());
          oss << std::hex << std::setfill('0') << std::setw(sizeof(std::size_t) * 2)
              << threadHash << std::dec;
        }
        break;
      case FormatToken::Level:
        oss << levelToString(level);
        break;
      case FormatToken::Message:
        oss << message;
        break;
      case FormatToken::File:
        oss << filename;
        break;
      case FormatToken::Line:
        oss << line;
        break;
      case FormatToken::Function:
        oss << function;
        break;
      }
    }
    oss << std::endl;
    return oss.str();
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

    return formatLogMessageInternal(level, message, segments, timestampFmt);
  }

  /// \brief Format a log message with source location information
  /// \param level The log level
  /// \param message The raw message content
  /// \param file Source file name (from __FILE__)
  /// \param line Source line number (from __LINE__)
  /// \param function Function name (from __func__)
  /// \return Formatted log string with newline
  static std::string formatLogMessage(Level level, const std::string &message,
                                      const char *file, int line, const char *function)
  {
    auto &data = getData();

    // Copy compiled segments and timestamp format under lock
    std::vector<FormatSegment> segments;
    std::string timestampFmt;
    {
      std::lock_guard<std::mutex> lock(data.mutex);
      if (data._compiledFormat.empty() && !data._logFormat.empty())
      {
        compileFormat(data._logFormat, data._compiledFormat);
      }
      segments = data._compiledFormat;
      timestampFmt = data.timestampFormat;
    }

    return formatLogMessageInternal(level, message, file, line, function, segments, timestampFmt);
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

/// \brief Legacy context prefix macro (deprecated - use format placeholders %F, %l, %f instead)
#define IORA_LOG_CONTEXT_PREFIX "[" << iora::core::detail::basename(__FILE__) << ":" << __LINE__ << " " << __func__ << "] "

/// \brief Stream-style logging macro with source location support
/// Uses format string placeholders (%F, %l, %f) for source location
#define IORA_LOG_WITH_LEVEL(level, msg)                                                            \
  do                                                                                               \
  {                                                                                                \
    std::ostringstream _oss;                                                                       \
    _oss << msg;                                                                                   \
    iora::core::Logger::log(iora::core::Logger::Level::level, _oss.str(),                         \
                            __FILE__, __LINE__, __func__);                                         \
  } while (0)

#define IORA_LOG_TRACE(msg) IORA_LOG_WITH_LEVEL(Trace, msg)
#define IORA_LOG_DEBUG(msg) IORA_LOG_WITH_LEVEL(Debug, msg)
#define IORA_LOG_INFO(msg) IORA_LOG_WITH_LEVEL(Info, msg)
#define IORA_LOG_WARN(msg) IORA_LOG_WITH_LEVEL(Warning, msg)
#define IORA_LOG_ERROR(msg) IORA_LOG_WITH_LEVEL(Error, msg)
#define IORA_LOG_FATAL(msg) IORA_LOG_WITH_LEVEL(Fatal, msg)

/// \brief Printf-style logging macros with source location support
/// Source location is passed to logger and formatted according to format string.
/// Use placeholders %F (file), %l (line), %f (function) in format string to display source location.
/// \warning Messages are limited to 4096 bytes (including null terminator).
///          Longer messages will be silently truncated by std::snprintf.
///          For messages exceeding this limit, use Logger::tracef() directly.
/// \note Uses stack buffer for performance - suitable for most logging scenarios.
#define IORA_LOG_TRACEF(fmt, ...)                                                                      \
  do                                                                                                   \
  {                                                                                                    \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::log(iora::core::Logger::Level::Trace, _buf,                                   \
                            __FILE__, __LINE__, __func__);                                             \
  } while (0)

#define IORA_LOG_DEBUGF(fmt, ...)                                                                      \
  do                                                                                                   \
  {                                                                                                    \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::log(iora::core::Logger::Level::Debug, _buf,                                   \
                            __FILE__, __LINE__, __func__);                                             \
  } while (0)

#define IORA_LOG_INFOF(fmt, ...)                                                                       \
  do                                                                                                   \
  {                                                                                                    \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::log(iora::core::Logger::Level::Info, _buf,                                    \
                            __FILE__, __LINE__, __func__);                                             \
  } while (0)

#define IORA_LOG_WARNF(fmt, ...)                                                                       \
  do                                                                                                   \
  {                                                                                                    \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::log(iora::core::Logger::Level::Warning, _buf,                                 \
                            __FILE__, __LINE__, __func__);                                             \
  } while (0)

#define IORA_LOG_ERRORF(fmt, ...)                                                                      \
  do                                                                                                   \
  {                                                                                                    \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::log(iora::core::Logger::Level::Error, _buf,                                   \
                            __FILE__, __LINE__, __func__);                                             \
  } while (0)

#define IORA_LOG_FATALF(fmt, ...)                                                                      \
  do                                                                                                   \
  {                                                                                                    \
    char _buf[4096];                                                                                   \
    std::snprintf(_buf, sizeof(_buf), fmt, ##__VA_ARGS__);                                             \
    iora::core::Logger::log(iora::core::Logger::Level::Fatal, _buf,                                   \
                            __FILE__, __LINE__, __func__);                                             \
  } while (0)

inline LoggerStream Logger::stream(Logger::Level level) { return LoggerStream(level); }
} // namespace core
} // namespace iora