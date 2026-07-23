// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <cassert>
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
#include <optional>
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

  /// \brief (Re)initialize the logger. NOT concurrency-safe against active
  /// logging: init() clears the queues and resets mode/level under the lock but
  /// does NOT drain in-flight handler invocations, so calling it concurrently
  /// with live logging can silently drop queued raw entries. Call it once at
  /// startup (or while quiescent), not as live reconfiguration.
  static void init(Level level = Level::Info, const std::string &filePath = "", bool async = false,
                   int retentionDays = 7, const std::string &timeFormat = "%Y-%m-%d %H:%M:%S")
  {
    auto &data = getData();
    std::unique_lock<std::mutex> lock(data.mutex);

    // A teardown may be in flight. Clearing `exit` under a worker that has already
    // been told to stop makes it park again forever, hanging that teardown's
    // join(); and returning while a stopping worker still holds `workerRunning`
    // would leave async mode with no drainer (the spawn gate below would skip).
    if (data.exit && data.workerRunning)
    {
      if (data.workerThreadId == std::this_thread::get_id())
      {
        // We ARE the stopping worker (init() from inside a handler). We cannot
        // wait for ourselves, and clearing `exit` would CANCEL the stop request a
        // teardown is already blocked on in join() — that join would never return.
        // The pending teardown wins; a later init() from a normal thread will
        // re-initialize.
        std::cerr << "Logger: init() called from the logger worker thread while a shutdown is "
                     "in flight; the pending shutdown wins (logger not re-initialized)"
                  << std::endl;
        return;
      }
      // A depth>0 caller's own handler frame is pinned in externalHandlerInflight
      // for the whole wait. It MUST register that frame in `frozen` exactly as the
      // teardown paths do — otherwise a worker parked in its own self-clear can
      // never satisfy inflight == frozen, and we are waiting for that worker:
      // circular wait. Declared after `lock`, so it is released under the mutex.
      std::optional<FrozenScope> frozen;
      const int depth = handlerReentryDepth();
      if (depth > 0)
      {
        frozen.emplace(data, depth);
        data.externalHandlerDone.notify_all(); // required — see the drain helper
      }
      const unsigned stoppingGeneration = data.workerGeneration;
      waitForWorkerExitLocked(lock, data, stoppingGeneration);
    }

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
    data.queue = {};
    data.rawQueue = {};

    rotateLogFileIfNeeded();

    // Gate on workerRunning, NOT joinable(): after a teardown moved the thread
    // object out (or detached it), joinable() is false while that worker may still
    // be running. Spawning a second one here would leave two workers draining the
    // same queues, and the first would never observe `exit` again.
    if (data.asyncMode.load(std::memory_order_relaxed) && !data.workerRunning)
    {
      // Publish AFTER successful construction: std::thread's ctor can throw
      // (EAGAIN). Publishing first would leave workerRunning==true with no worker
      // — every later init() would refuse to spawn one, and ~LoggerData would wait
      // forever for an exit that can never be published. Safe to publish after,
      // because init() holds the mutex across the spawn and runWorker's first act
      // is to acquire it.
      assert(!data.workerThread.joinable()); // teardown always moves it out first
      data.workerThread = std::thread(runWorker);
      data.workerThreadId = data.workerThread.get_id();
      data.workerRunning = true;
      ++data.workerGeneration;
    }
  }

  static void flush()
  {
    auto &data = getData();
    // Declared BEFORE the lock so it is destroyed AFTER it: if the sink drain
    // throws (bad_alloc, or cout with exceptions enabled), unwinding would
    // otherwise release the stashed USER exception object — running its
    // destructor — while data.mutex is still held.
    std::exception_ptr handlerError;
    std::unique_lock<std::mutex> lock(data.mutex);

    // Flush the external-handler queue first. A handler exception propagates to
    // this synchronous caller, but must NOT skip the normal-queue/file flush
    // below — stash it and rethrow after the sinks are flushed.
    try
    {
      while (deliverOneRawEntryLocked(lock, data))
      {
      }
    }
    catch (...)
    {
      handlerError = std::current_exception();
    }

    // Always flush queue for both sync and async modes
    drainNormalQueueLocked(data);
    flushSinkLocked(data);

    if (handlerError)
    {
      // Release first: rethrowing under the lock would touch the user exception
      // object (and run its destructor on the unwind path) with data.mutex held.
      lock.unlock();
      std::rethrow_exception(handlerError);
    }
  }

  static void shutdown()
  {
    auto &data = getData();
    // A throwing handler or sink during the final drain must not prevent shutdown
    // from stopping and reaping the worker (the worker's own loop swallows both
    // handler and sink exceptions); otherwise a throwing handler could leave the
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

    teardownAndReapWorker(data, /*report=*/true);
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
    // Declared BEFORE the lock so the PREVIOUS handler — and everything it
    // captured — is destroyed AFTER the mutex is released. Destroying a
    // std::function under data.mutex runs arbitrary user destructors under a
    // non-recursive lock; a capture whose destructor logs would re-enter
    // logDispatch and self-deadlock.
    ExternalHandler doomed;
    {
      std::unique_lock<std::mutex> lock(data.mutex);
      // Declared AFTER the lock so the frozen registration is released while
      // data.mutex is still held. A normal tear-out is pinned only for its own
      // wait, unlike the teardown paths (see the helper's doc).
      std::optional<FrozenScope> frozen;

      // Null the gate and drain any in-flight invocation of the PREVIOUS handler
      // before swapping it out — the same tear-out UAF as clearExternalHandler.
      // Messages logged during this swap window are not delivered to either
      // handler (accepted). They take the normal queue path, whose sink is the
      // CONSOLE here — file logging is off while a handler is installed. See
      // tearOutGateAndDrainInflightLocked for the deadlock-freedom / UAF-safety
      // argument (self-tearer vs external drain predicates).
      tearOutGateAndDrainInflightLocked(lock, data, doomed, frozen);

      // Discard any entries still queued for the PREVIOUS handler. Rerouting them
      // to the normal sink would print to cout while the NEW handler is active
      // (which disables console/file output), and delivering them to the new
      // handler would be misdelivery — so, consistent with the swap-window "not
      // delivered to either handler" semantics above, they are dropped. Emptying
      // rawQueue here also prevents the orphaned-queue busy-spin.
      data.rawQueue = {};

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
  }

  /// \brief Remove external log handler and restore normal logging.
  ///
  /// POSTCONDITION (precise): on return, no invocation of the handler that was
  /// installed when this call began is still running, and this call nulled the
  /// gate. It does NOT guarantee that no handler is installed on return: a
  /// concurrent setExternalHandler may reinstall one while this call is parked in
  /// the drain, so a caller must not race clear against set and then treat the
  /// gate as closed. It also does NOT wait out PEER SELF-TEARERS when called from
  /// inside the handler — see tearOutGateAndDrainInflightLocked for the exact
  /// guarantee each caller class receives.
  static void clearExternalHandler()
  {
    auto &data = getData();
    // Declared BEFORE the lock — see setExternalHandler: the removed handler's
    // captured state must be destroyed with data.mutex released.
    ExternalHandler doomed;
    {
      std::unique_lock<std::mutex> lock(data.mutex);
      std::optional<FrozenScope> frozen; // released under the lock at scope exit
      // Null the gate and drain any in-flight invocation before returning — so a
      // [this]-capturing handler's object can never be destroyed mid-call. Covers
      // the sync log(), flush(), and async-worker paths.
      tearOutGateAndDrainInflightLocked(lock, data, doomed, frozen);

      // Reroute any entries still queued for the removed handler so they are not
      // orphaned in rawQueue (which would busy-spin the worker) and not lost —
      // they land on the normal queue for file/console. SKIPPED when a racing
      // setExternalHandler reinstalled a handler while we were parked: those
      // entries belong to the NEW handler, and rerouting them would print to cout
      // while an external handler is active (console output is meant to be off).
      if (!data.useExternalHandler)
      {
        rerouteRawQueueToNormalQueueLocked(data);
        data.cv.notify_one(); // wake the worker to drain the rerouted entries
      }
      // File logging will be restored on next log call via rotateLogFileIfNeeded
    }
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
    /// LOCK DISCIPLINE (single source of truth for this class):
    ///  - `mutex` is the ONLY mutex in the logger and the LOWEST logger-owned lock:
    ///    the only locks acquired beneath it are the stream/stdio locks of the sink
    ///    (see the sink-I/O bullet below). Keep it lowest if a second lock is ever
    ///    added. The converse statement, that `mutex` is never taken while another
    ///    lock is held, is neither true nor enforceable.
    ///    CAVEAT — this does NOT make "log while holding your own lock"
    ///    unconditionally safe. It is safe with respect to `mutex`, but in SYNC mode
    ///    logDispatch invokes the external handler ON THE CALLER'S STACK with the
    ///    caller's lock still held, creating a lock-order edge callerLock ->
    ///    (every lock the handler takes) that this class cannot see. A handler that
    ///    acquires the very lock the logging call site holds self-deadlocks on it;
    ///    cross-thread, the ABBA against another site that takes them in the other
    ///    order is equally reachable. Copy-then-invoke closes the LIBRARY's lock,
    ///    not the CALLER's. Do not log under a lock the handler may also acquire.
    ///  - `workerThread` is assigned under `mutex` by init(), so shutdown() and
    ///    ~LoggerData MOVE it out under the lock and join the local copy — reading
    ///    or joining the member unlocked races init() and can double-join.
    ///  - Sink I/O (rotateLogFileIfNeeded, ofstream/cout writes) and the drain
    ///    stall diagnostics ARE performed under `mutex`: ordering of log lines is
    ///    the deliberate priority over the latency cost of holding the lock across
    ///    file I/O. This orders the stream/stdio locks BELOW `mutex`, so no code
    ///    may take `mutex` while holding a stream lock — a user streambuf on
    ///    cout/cerr that logs would self-deadlock on this non-recursive mutex.
    ///  - It is NEVER held across a user callback (copy-then-invoke: every dispatch
    ///    site copies the handler under the lock, unlocks, then invokes) and never
    ///    across the DESTRUCTION of a user callback: clear/setExternalHandler and
    ///    both teardown paths move the doomed std::function into a caller-owned
    ///    local destroyed after unlocking, and the dispatch sites destroy their
    ///    in-flight copy inside the unlocked window via HandlerCopyDropper. A catch
    ///    site inside a locked scope either routes through reportAndReleaseUnlocked
    ///    or stashes into an exception_ptr declared ABOVE the lock (flush(),
    ///    teardownAndReapWorker) — ex.what() and the destruction of a caught
    ///    exception object are user code too.
    ///    STILL under-lock user code, and NOT a complete close-out on its own:
    ///      (a) the handler COPY (dispatch sites), the tear-out SWAP
    ///          (tearOutGateAndDrainInflightLocked) and the handler INSTALL
    ///          (setExternalHandler's move-assign) — backlog 2026-07-22-3 reduces
    ///          these to a refcount bump;
    ///      (b) sink and diagnostic I/O through a user streambuf on cout/cerr —
    ///          see the sink-I/O bullet above; OUTSIDE that backlog's scope.
    ///    Do not restate a narrower claim here; docs/iora/logger_external_handlers.md
    ///    enumerates every site.
    ///  - `externalHandlerInflight` and `externalHandlerFrozen` are mutated AND read
    ///    only under it.
    ///  - `cv` has exactly ONE waiter (the worker), so notify_one is correct.
    ///    `externalHandlerDone` can have MANY waiters (concurrent drainers), so it
    ///    requires notify_all — notify_one there would lose wakeups.
    std::mutex mutex;
    std::condition_variable cv;
    std::queue<std::string> queue;
    std::queue<std::pair<Level, std::string>> rawQueue; // For external handlers
    std::thread workerThread;
    /// Worker-stop predicate. Atomic only as defence in depth: it is written AND
    /// read exclusively under `mutex` on every path, and it MUST stay that way —
    /// an unlocked write can be lost if the worker is between its predicate check
    /// and parking, hanging join() at teardown. The mutex, not the atomicity, is
    /// what makes the wakeup safe.
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
    /// Sum of the reentry-depth contributions of self-tearing invocations
    /// currently BLOCKED in a clear/setExternalHandler drain wait (a handler that
    /// re-enters to clear/swap itself). Plain int, mutated and read ONLY under
    /// `mutex` (never a lockless atomic). Invariant:
    /// 0 <= externalHandlerFrozen <= externalHandlerInflight always — each frozen
    /// unit corresponds to a distinct pinned in-flight frame. External (depth-0)
    /// callers NEVER touch it. The deadlock-freedom / UAF-safety argument lives in
    /// ONE place: tearOutGateAndDrainInflightLocked. Do not restate it here.
    int externalHandlerFrozen = 0;
    /// Signalled (notify_all) on every decrement of externalHandlerInflight, and
    /// when the worker clears `workerRunning`. Dedicated CV (not `cv`) so
    /// drain-waiters never consume worker wakeups.
    std::condition_variable externalHandlerDone;
    /// TRUE from the moment init() spawns the worker until the worker's LAST
    /// action before returning. Guarded by `mutex`. Distinct from
    /// workerThread.joinable(): teardown MOVES the thread object out (and the
    /// self-teardown path detaches it), so joinable() goes false while the worker
    /// is still running and still touching this object. Two things depend on the
    /// distinction: init() must not spawn a SECOND worker alongside a live one,
    /// and ~LoggerData must not destroy this object while a detached worker is
    /// still inside its loop.
    bool workerRunning = false;
    /// Incremented under `mutex` on every spawn. `workerRunning` alone is
    /// LEVEL-triggered: a racing init() can spawn a NEW worker that re-asserts it,
    /// and a waiter for the OLD worker would then block for one it never asked to
    /// stop. Every "wait for the worker to exit" predicate is therefore stamped
    /// with the generation it cares about. (A thread id would mostly work but can
    /// be recycled after the old worker exits; a counter cannot.)
    unsigned workerGeneration = 0;
    /// Id of the live worker, valid only while `workerRunning`. Guarded by
    /// `mutex`. Used ONLY to answer "am I the worker?" on teardown paths, so a
    /// thread cannot wait for itself to exit. (It is cleared when the worker
    /// exits, so it cannot go stale across thread-id reuse the way the removed
    /// handler-self-detection scheme could.)
    std::thread::id workerThreadId;
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
      // Static destruction: same protocol as shutdown(), silent. Sharing ONE
      // implementation is deliberate — the two copies of this sequence drifted
      // apart twice during review (a hand-inlined depth-0 predicate that hung at
      // exit, and a frozen-release timing that deadlocked the join).
      try
      {
        Logger::teardownAndReapWorker(*this, /*report=*/false);
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
  /// re-enters to swap or clear the handler — and take the frozen-inflight
  /// self-tearer branch (wait inflight == externalHandlerFrozen) instead of the
  /// external full drain; see tearOutGateAndDrainInflightLocked for why. Replaces
  /// the former workerThreadId
  /// self-detection, which could go stale once the worker was joined (a later
  /// thread reusing that OS id would misfire) and never covered handler
  /// invocations on the sync log() path or the flush() thread at all.
  /// \note CROSS-.so ABI PRECONDITION (R-12): the frozen-inflight drain
  /// (tearOutGateAndDrainInflightLocked) selects the self-tearer vs external
  /// branch on this depth, so correctness requires ONE `thread_local` instance
  /// process-wide. In the shared build that is ENFORCED by defining this function
  /// once in libiora_core.so (above), not left to vague-linkage merging.
  /// iora_test_plugin_isolation asserts the INSTANCE — `&handlerReentryDepth()` —
  /// is identical host<->plugin, because that is the property the drain's depth
  /// branch actually depends on and it survives any future re-inlining. (History:
  /// while this was header-inline, a Release build emitted a per-.so copy of the
  /// FUNCTION — the addresses differed while the instances matched — so a
  /// function-symbol assertion failed under -O3 without indicating any real
  /// hazard. Out-of-lining removed the ambiguity; the instance check is kept
  /// because it is the stronger statement.)
#if defined(IORA_CORE_SHARED) || defined(IORA_CORE_BUILDING)
  // Declared here, DEFINED ONCE in src/core/iora_core.cpp — the same out-of-line
  // singleton pattern as getData(). Header-inline would leave the single-instance
  // property to vague-linkage merging, which is not guaranteed under the
  // RTLD_LOCAL dlopen the plugin loader uses: the COMDAT lands in libiora_core.so
  // only if some TU there incidentally odr-uses it. If that ever lapsed, a
  // plugin's self-clear would read depth==0, take the external inflight==0 branch,
  // and self-deadlock on its own pinned frame — silently, in Release.
  static int &handlerReentryDepth();
#else
  static int &handlerReentryDepth()
  {
    static thread_local int depth = 0;
    return depth;
  }
#endif

private:
  /// \brief RAII marker: the current thread is executing an external handler for
  /// the duration of the (unlocked) callback, so a self-call into
  /// clear/setExternalHandler is detected. Exception-safe. PRIVATE: constructing
  /// one outside a real invocation would raise handlerReentryDepth() without a
  /// matching in-flight frame, breaking the frozen <= inflight invariant — a
  /// later self-clear from that thread would then wait on an unsatisfiable
  /// predicate (release builds do not carry the assert).
  struct HandlerInvocationScope
  {
    HandlerInvocationScope() { ++handlerReentryDepth(); }
    ~HandlerInvocationScope() { --handlerReentryDepth(); }
    HandlerInvocationScope(const HandlerInvocationScope &) = delete;
    HandlerInvocationScope &operator=(const HandlerInvocationScope &) = delete;
  };

  // Tear-out drain internals. NOT API: constructing a FrozenScope or calling the
  // drain/delivery helpers from outside would corrupt the frozen <= inflight
  // invariant (which is only assert-checked in debug builds). getData() and
  // handlerReentryDepth() stay public above — both are taken by address across the
  // plugin ABI boundary.

  /// \brief RAII marker: a self-tearing invocation registers its reentry-depth
  /// contribution into externalHandlerFrozen for the duration of its drain wait in
  /// clear/setExternalHandler. Two properties are unique to this guard (the WHY of
  /// the protocol itself lives in tearOutGateAndDrainInflightLocked):
  ///  - It MUST be constructed and destroyed while `data.mutex` is held. It is
  ///    declared inside the drain helper, whose `lock` parameter is held for the
  ///    guard's whole lifetime (condition_variable::wait re-acquires the lock even
  ///    when it propagates an exception), so `frozen -= depth` provably runs under
  ///    the mutex on the normal AND the throwing path.
  ///  - It NEVER notifies. See the no-park-notify proof in the drain helper.
  struct FrozenScope
  {
    FrozenScope(LoggerData &data, int depth) : _data(data), _depth(depth)
    {
      _data.externalHandlerFrozen += _depth;
      assert(_data.externalHandlerFrozen >= 0 &&
             _data.externalHandlerFrozen <= _data.externalHandlerInflight);
    }
    ~FrozenScope()
    {
      _data.externalHandlerFrozen -= _depth;
      assert(_data.externalHandlerFrozen >= 0 &&
             _data.externalHandlerFrozen <= _data.externalHandlerInflight);
    }
    FrozenScope(const FrozenScope &) = delete;
    FrozenScope &operator=(const FrozenScope &) = delete;

  private:
    LoggerData &_data;
    int _depth;
  };

  /// \brief Releases a caller-held FrozenScope UNDER `data.mutex`, on every exit
  /// path including an exception. Teardown keeps its frozen registration alive
  /// past the locked scope (across the worker join), so the release cannot simply
  /// ride the scope of the unique_lock the way clear/setExternalHandler's does.
  struct FrozenReleaser
  {
    // Explicit ctor, NOT aggregate initialization: a class with a user-DECLARED
    // (even deleted) constructor stops being an aggregate in C++20, so
    // `FrozenReleaser r{data, slot};` would break on the next standard bump.
    FrozenReleaser(LoggerData &data, std::optional<FrozenScope> &slot)
        : _data(data), _slot(slot)
    {
    }
    ~FrozenReleaser()
    {
      if (_slot)
      {
        std::lock_guard<std::mutex> lock(_data.mutex);
        _slot.reset();
      }
    }
    FrozenReleaser(const FrozenReleaser &) = delete;
    FrozenReleaser &operator=(const FrozenReleaser &) = delete;

  private:
    LoggerData &_data;
    std::optional<FrozenScope> &_slot;
  };

  /// \brief Wait for `pred` on externalHandlerDone, emitting a periodic diagnostic
  /// while it is unsatisfied. It NEVER gives up and proceeds: a bounded
  /// wait-then-tear-out would destroy the handler's captured state while an
  /// invocation is still running (a use-after-free — strictly worse than a hang,
  /// and explicitly rejected for this protocol). The diagnostic exists because
  /// these drains now also gate shutdown() and static destruction: a handler
  /// wedged on a user lock would otherwise hang process exit with no output at
  /// all. `lock` is held on entry and on return.
  /// `what` names the thing being waited for — this helper serves several
  /// predicates (handler drain, worker exit), and a stall message that names the
  /// wrong subsystem is worse than none, since it is the ONLY output a wedged
  /// process produces. `kStallReportInterval` is DIAGNOSTIC ONLY: no correctness
  /// property may depend on it (every satisfying state change notifies).
  template <typename Predicate>
  static void waitWithStallDiagnosticLocked(std::unique_lock<std::mutex> &lock, LoggerData &data,
                                            const char *what, Predicate pred)
  {
    constexpr auto kStallReportInterval = std::chrono::seconds(5);
    while (!data.externalHandlerDone.wait_for(lock, kStallReportInterval, pred))
    {
      std::cerr << "Logger: still waiting for " << what << " (inflight="
                << data.externalHandlerInflight << ", frozen=" << data.externalHandlerFrozen
                << ", workerRunning=" << (data.workerRunning ? "yes" : "no")
                << "); still waiting — proceeding early would be unsafe" << std::endl;
    }
  }

  /// \brief Stop and reap the worker, then drain what is left. ONE implementation
  /// shared by shutdown() and ~LoggerData: these two sequences drifted apart twice
  /// during review, each time producing a hang (a hand-inlined depth-0 predicate
  /// that could not be satisfied at depth > 0, and a frozen-release timing that
  /// deadlocked the join). `report` selects operator diagnostics (shutdown) versus
  /// silence (static destruction).
  ///
  /// DEPTH MATTERS. Reached from inside a handler (shutdown() called by a handler,
  /// or std::exit() running static destructors on that thread) this runs at depth
  /// 1 with its own frame pinned in externalHandlerInflight for the whole
  /// sequence — including the join. The frozen registration is therefore held
  /// until AFTER the join and released under the mutex by FrozenReleaser;
  /// releasing it at the end of the drain wait would leave a peer parked in its
  /// own tear-out unsatisfiable while we block in join() — a circular wait.
  static void teardownAndReapWorker(LoggerData &data, bool report)
  {
    // `doomed` outlives every lock scope: destroying a handler runs user capture
    // destructors, which must not happen under data.mutex.
    ExternalHandler doomed;
    std::thread worker;
    std::optional<FrozenScope> frozen;
    FrozenReleaser frozenReleaser(data, frozen); // releases it UNDER the mutex
    bool selfIsWorker = false;
    unsigned stoppedGeneration = 0;
    {
      std::unique_lock<std::mutex> lock(data.mutex);
      tearOutGateAndDrainInflightLocked(lock, data, doomed, frozen);
      // Entries queued for the handler after the drain would otherwise be silently
      // dropped (the worker gates rawQueue on useExternalHandler, now false).
      // UNGUARDED, unlike clearExternalHandler: at teardown, printing a racing
      // reinstall's entries to the console beats losing them.
      rerouteRawQueueToNormalQueueLocked(data);
      data.exit = true;
      stoppedGeneration = data.workerGeneration;
      selfIsWorker = (data.workerThreadId == std::this_thread::get_id());
      worker = std::move(data.workerThread);
    }
    data.cv.notify_one(); // `cv` has exactly one waiter — see LOCK DISCIPLINE

    if (worker.joinable())
    {
      if (selfIsWorker)
      {
        if (report)
        {
          std::cerr << "Logger: shutdown() called from the logger worker thread; "
                       "skipping self-join"
                    << std::endl;
        }
        worker.detach();
      }
      else
      {
        // A throwing join would leave `worker` joinable, and ~thread would then
        // call std::terminate during unwinding — erasing the real diagnosis.
        try
        {
          worker.join();
        }
        catch (const std::exception &ex)
        {
          if (report)
          {
            std::cerr << "Logger: join of the worker thread failed: " << ex.what()
                      << "; detaching" << std::endl;
          }
          worker.detach();
        }
      }
    }

    // Declared BEFORE the lock, exactly as flush() does, so they are destroyed
    // AFTER it: an exception_ptr holding a USER exception object must never be
    // released with data.mutex held. Reporting happens after the locked scope
    // closes, so the block below is ONE uninterrupted critical section — an
    // earlier version reported inline via reportAndReleaseUnlocked, whose
    // unlock/relock silently invalidated the "worker is reaped" conclusion that
    // waitForWorkerExitLocked establishes at the top of it (a racing init() could
    // spawn a new worker in that window, and ~LoggerData would then destroy this
    // object under a live worker).
    std::exception_ptr sinkError;
    std::exception_ptr flushError;
    {
      std::unique_lock<std::mutex> lock(data.mutex);
      // A worker we could not join (detached here, or by an earlier self-teardown)
      // is still inside its loop touching this object after every drain predicate
      // is satisfied. Wait for ITS exit publication — keyed on the generation, so a
      // racing init() that spawns a NEW worker cannot strand us waiting for one we
      // never asked to stop. Skipped when WE are that worker.
      if (!selfIsWorker)
      {
        waitForWorkerExitLocked(lock, data, stoppedGeneration);
      }
      // Nothing will ever drain what the reroute above put on the normal queue once
      // the worker is gone — write it out rather than destroy it. Swallow a
      // throwing sink: shutdown() is routinely called from destructors, atexit and
      // noexcept teardown, where an escaping exception is std::terminate. Before
      // the two teardown paths were merged, shutdown() guarded this and
      // ~LoggerData relied on its own catch(...) — keeping the guard HERE keeps the
      // two paths identical, which is the point of sharing the implementation.
      // Stash, then report+release with the lock RELEASED. Handling the catch
      // INLINE here would run ex.what() and the USER exception object's destructor
      // under data.mutex — the hazard reportAndReleaseUnlocked exists to remove on
      // the worker path, and that flush() avoids by declaring its exception_ptr
      // above the lock. A user streambuf on cout can throw here, so this path is
      // reachable; a what() or exception destructor that logs would self-deadlock.
      try
      {
        drainNormalQueueLocked(data);
      }
      catch (...)
      {
        sinkError = std::current_exception();
      }
      // Runs even when the drain threw, so buffered output still reaches the sink.
      try
      {
        flushSinkLocked(data);
      }
      catch (...)
      {
        flushError = std::current_exception();
      }
    }
    // Lock released. Report and release the USER exception objects here: noexcept,
    // so this cannot escape ~LoggerData or shutdown() (both run from destructors,
    // atexit and noexcept teardown, where an escape is std::terminate).
    reportAndReleaseNoLock(sinkError, "sink threw during the teardown drain", report);
    reportAndReleaseNoLock(flushError, "sink threw during the teardown flush", report);
  }

  /// \brief Report a caught exception and release it with `lock` RELEASED.
  /// Both `ex.what()` and the destruction of the exception object at the end of a
  /// catch block are USER code. runHandlerUnlocked rethrows with data.mutex
  /// RE-ACQUIRED (and the sink drains run under it), so reporting inline would run
  /// that user code under the non-recursive mutex — the same hazard already fixed
  /// for the handler itself (invocation, copy and destruction). An exception whose
  /// destructor or what() logs would otherwise self-deadlock here.
  /// A catch site inside a locked scope must EITHER route through here OR apply the
  /// equivalent structural rule — declare the exception_ptr ABOVE the unique_lock
  /// and report/release after the scope closes, as flush() and teardownAndReapWorker
  /// do. What is never acceptable is handling it inline under the lock.
  /// `report=false` (static destruction) still needs the unlock, because releasing
  /// the last exception_ptr reference destroys the USER exception object; only the
  /// diagnostic is suppressed.
  /// Core of the above, holding NO lock. `noexcept` is load-bearing, not decorative:
  /// both runWorker call sites invoke the reporter OUTSIDE the try/catch that keeps
  /// exceptions off the worker std::thread, so a throwing reporter would escape
  /// runWorker and std::terminate — defeating the very guard that wraps the drain.
  /// `ex.what()` is user virtual code and a stream with an exceptions mask rethrows,
  /// so the report genuinely can throw. Swallowing keeps the release+return
  /// unconditional. No-op on a null `err`, so callers need not pre-check.
  static void reportAndReleaseNoLock(std::exception_ptr &err, const char *context,
                                     bool report) noexcept
  {
    if (!err)
    {
      return;
    }
    if (report)
    {
      try
      {
        std::rethrow_exception(err);
      }
      catch (const std::exception &ex)
      {
        std::cerr << "Logger: " << context << ": " << ex.what() << std::endl;
      }
      catch (...)
      {
        std::cerr << "Logger: " << context << " (non-std exception)" << std::endl;
      }
    }
    err = nullptr; // release the last reference to the USER object, unlocked
  }

  static void reportAndReleaseUnlocked(std::unique_lock<std::mutex> &lock,
                                       std::exception_ptr &err, const char *context,
                                       bool report = true)
  {
    lock.unlock();
    reportAndReleaseNoLock(err, context, report);
    lock.lock(); // only throw site left is a terminal std::system_error
  }

  /// \brief Wait for the worker identified by `workerId` to publish its exit.
  /// Waiting on the bare `!workerRunning` flag is WRONG: a racing init() can spawn
  /// a NEW worker between the join and this wait, and the waiter would then block
  /// for a worker it never asked to stop (a hang). Bind the wait to the identity.
  /// No-ops when there is nothing to wait for, or when WE are that worker.
  static void waitForWorkerExitLocked(std::unique_lock<std::mutex> &lock, LoggerData &data,
                                      unsigned generation)
  {
    waitWithStallDiagnosticLocked(
      lock, data, "the logger worker thread to exit",
      [&data, generation]
      { return !data.workerRunning || data.workerGeneration != generation; });
  }

  /// \brief Null the external-handler gate fields and drain in-flight invocations
  /// before a tear-out (clear/setExternalHandler). THIS IS THE ONE PLACE the drain
  /// protocol is argued; other sites point here rather than restating it.
  ///
  /// Given `lock` HELD on `data.mutex`. The removed handler is MOVED into `doomed`
  /// (rather than destroyed here) because destroying a std::function runs arbitrary
  /// user capture destructors — the caller owns `doomed` and destroys it with the
  /// mutex released. Nulling the gate here, not at the call site, is what prevents
  /// any new invocation OF THE TORN-OUT HANDLER from starting (runWorker/flush()/
  /// log() all gate on useExternalHandler under the lock), so that precondition is
  /// code-enforced, not a caller obligation. The depth-0 predicate inflight == 0 is
  /// therefore a global quiescent point and is UAF-safe.
  /// It does NOT make `externalHandlerInflight` monotone non-increasing during the
  /// wait: the wait releases the mutex, so a racing setExternalHandler can re-arm
  /// the gate and invocations of the NEW handler can raise inflight again. That is
  /// the drain-STARVATION limitation (accepted; see the tracker's
  /// accepted_limitations), not a safety hole — the safety argument rests on what
  /// observing the predicate means, never on monotonicity.
  ///
  /// Deadlock-free AND use-after-free-free under concurrent self-tear-out
  /// (tracker 2026-07-21-3, Option 2 frozen-inflight accounting):
  ///  - Self-tearer (handlerReentryDepth() > 0): registers `depth` into
  ///    externalHandlerFrozen (RAII, under the lock) and waits the LIVE predicate
  ///    inflight == frozen — draining every NON-frozen invocation. When two
  ///    self-tearers block concurrently, the one whose registration closes the gap
  ///    self-observes it under the same held lock and does not park; it then drives
  ///    a notifying --inflight that releases the peer. A park-site notify_all IS
  ///    required on the frozen registration: a TEARDOWN caller self-catches and
  ///    then blocks in worker.join() while still holding its registration, so it
  ///    does NOT promptly drive the notifying --inflight that clear/set do — a peer
  ///    it just satisfied would otherwise wait out kStallReportInterval. The
  ///    FrozenScope DESTRUCTOR still needs no notify: since frozen <= inflight
  ///    always, a frozen decrement can only falsify inflight == frozen, and it
  ///    never affects inflight == 0. notify_all (never notify_one) on every
  ///    --inflight remains sufficient AND required.
  ///  - External caller (depth == 0): may destroy the handler's captured object, so
  ///    it MUST wait a genuine full drain inflight == 0 and NEVER subtracts frozen.
  ///
  /// GUARANTEE DELIVERED, precisely — the two callers get DIFFERENT strengths:
  ///  - depth == 0: no invocation of the torn-out handler is running on return.
  ///    This is the only safe basis for destroying an object the handler captured.
  ///  - depth  > 0 (self-tear-out): only every NON-self-tearing invocation has
  ///    exited. PEER invocations that are themselves tearing out may still be
  ///    executing handler code — and will still dereference their captures after
  ///    their own tear-out returns. This is the unavoidable price of deadlock
  ///    freedom (waiting on a peer that is equally pinned is the circular wait this
  ///    fix exists to remove). NEVER destroy a captured object on the strength of a
  ///    self-clear; route lifetime-critical teardown through a depth-0 call.
  ///
  /// Depth is provably 0 or 1 (every dispatch site gates handlerReentryDepth()==0),
  /// so frozen reduces to a count of parked self-tearers; handlerReentryDepth() is
  /// retained over a literal 1 only as defensive self-documentation.
  /// `frozenSlot` receives the self-tearer's frozen registration when
  /// handlerReentryDepth() > 0. It is NOT released when this function returns: the
  /// caller owns it and MUST destroy it under `data.mutex`. This matters because
  /// `frozen` means "pinned frames that can never decrement", and a caller's frame
  /// stays pinned for as long as the caller is inside the handler — which for a
  /// TEARDOWN caller is longer than its own wait: it goes on to set `exit` and
  /// JOIN the worker. Releasing the registration at the end of the wait (as an
  /// earlier version did) makes a peer parked in its own tear-out unsatisfiable
  /// while this thread blocks in join() — a circular wait, this task's own P0 on
  /// the teardown path. clear/setExternalHandler destroy the slot at the end of
  /// their locked scope; shutdown()/~LoggerData keep it until after the join.
  static void tearOutGateAndDrainInflightLocked(std::unique_lock<std::mutex> &lock,
                                                LoggerData &data, ExternalHandler &doomed,
                                                std::optional<FrozenScope> &frozenSlot)
  {
    // Null both gate fields together so no NEW invocation can start, THEN drain.
    // SWAP (not move-then-null): a moved-from std::function is "valid but
    // unspecified", so a `= nullptr` afterwards could, in principle, destroy a live
    // target — running user destructors under data.mutex, the very hazard `doomed`
    // exists to prevent. swap() avoids that on libstdc++ (a bytewise swap of the
    // stored callable), but the standard does not GUARANTEE a swap runs no user
    // code: libc++ move-constructs and destroys small-buffer targets. The portable
    // close-out is holding the handler as shared_ptr<const ExternalHandler> so the
    // under-lock operation is a refcount bump — tracked in backlog 2026-07-22-3,
    // whose acceptance criterion is exactly "no user code runs under data.mutex on
    // ANY path". The caller destroys `doomed` after unlocking.
    data.externalHandler.swap(doomed);
    data.useExternalHandler = false;
    const int depth = handlerReentryDepth();
    if (depth > 0)
    {
      frozenSlot.emplace(data, depth);
      // REQUIRED, not belt-and-braces. A frozen increment can SATISFY a peer
      // already parked on inflight == frozen. The original proof said no notify
      // was needed because the incrementer self-catches and then promptly drives a
      // notifying --inflight — true while the only self-tearers were clear/set,
      // which return into the handler body. It is FALSE for a TEARDOWN caller:
      // it self-catches, keeps its registration, and then blocks in worker.join()
      // WITHOUT decrementing, so the peer it just satisfied has no wakeup event.
      // Measured before this notify: every depth>0 teardown stalled for exactly
      // kStallReportInterval (5.0s/iteration), i.e. liveness rested on a timer
      // documented as diagnostic-only — and reverting that wait to an untimed
      // wait() would have restored the P0 deadlock outright.
      data.externalHandlerDone.notify_all();
      waitWithStallDiagnosticLocked(
        lock, data, "in-flight external-handler invocations to drain",
        [&] { return data.externalHandlerInflight == data.externalHandlerFrozen; });
    }
    else
    {
      waitWithStallDiagnosticLocked(lock, data,
                                    "in-flight external-handler invocations to drain",
                                    [&] { return data.externalHandlerInflight == 0; });
    }
  }

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
                                        std::optional<ExternalHandler> &handler)
  {
    HandlerInvocationScope inv;          // declared FIRST -> destroyed LAST
    HandlerCopyDropper dropper(handler); // destroyed FIRST, i.e. still at depth 1
    // Formatting sits INSIDE both guards deliberately: it allocates and can throw.
    // If it threw BEFORE the dropper existed, the unwind would pass through
    // runHandlerUnlocked's catch — which RE-ACQUIRES data.mutex — and the caller
    // would then destroy the handler copy with the mutex held and at depth 0,
    // running user capture destructors under the non-recursive lock. Formatting
    // dispatches nothing and takes no lock, so doing it at depth 1 is
    // behaviour-preserving. RULE: everything throwable belongs inside the guards.
    std::string formattedMessage =
      formatLogMessageInternal(level, rawMessage, segments, timestampFmt);
    (*handler)(level, formattedMessage, rawMessage);
    // ORDER IS LOAD-BEARING (and it keeps the post-scope window free of user code:
    // once the dropper is destroyed here, nothing user-supplied runs between
    // ~HandlerInvocationScope and runHandlerUnlocked's --inflight).
    // The copy's destruction runs USER capture destructors,
    // so it must happen (a) with data.mutex released — hence inside this unlocked
    // window — AND (b) while handlerReentryDepth() is still 1. Between
    // ~HandlerInvocationScope (depth -> 0) and runHandlerUnlocked's --inflight this
    // thread is at depth 0 with its own frame STILL pinned in inflight: a capture
    // destructor calling clear/setExternalHandler there would take the depth-0
    // branch and wait inflight == 0 on its own pinned frame — unsatisfiable. With
    // the dropper destroyed first, that same destructor takes the self-tearer
    // branch (inflight == frozen) and returns immediately. Keep the post-scope
    // window free of logger re-entry.
  }

  /// \brief Write every entry on the NORMAL queue to its sink (file if open, else
  /// console), rotating as needed. Precondition: `data.mutex` HELD. Shared by
  /// flush() and runWorker() — the sibling of deliverOneRawEntryLocked, extracted
  /// for the same reason: one home for the sink-selection and rotation policy so
  /// the two drain sites cannot drift apart.
  static void drainNormalQueueLocked(LoggerData &data)
  {
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
  }

  /// \brief Make the SELECTED sink observable to a reader: the file stream if one
  /// is open, otherwise std::cout — which is fully buffered when stdout is
  /// redirected, so without this an explicit flush()/shutdown() would not surface
  /// console output until static destruction. One home for the rule; called from
  /// flush() and teardownAndReapWorker()'s final drain.
  static void flushSinkLocked(LoggerData &data)
  {
    if (data.fileStream)
    {
      data.fileStream->flush();
    }
    else
    {
      std::cout.flush();
    }
  }

  /// \brief Destroys an in-flight handler copy inside runHandlerUnlocked's
  /// UNLOCKED window AND while handlerReentryDepth() is still >= 1 (declare it
  /// AFTER the HandlerInvocationScope so it is destroyed BEFORE it). Both
  /// properties are required: unlocked so the user's capture destructors do not
  /// run under data.mutex, and at depth >= 1 so a destructor that re-enters the
  /// logger is depth-gated (a log() goes to the normal queue instead of
  /// re-dispatching unboundedly) and a destructor that calls
  /// clear/setExternalHandler takes the SELF-TEARER branch — at depth 0 it would
  /// take the external branch and wait inflight == 0 on its own pinned frame,
  /// which is unsatisfiable. Necessary
  /// because runHandlerUnlocked re-acquires `data.mutex` before returning: a
  /// handler copy left to die at the enclosing scope's exit would run the user's
  /// capture destructors under the lock — and after a concurrent tear-out moved
  /// the stored handler into `doomed`, this in-flight copy is frequently the LAST
  /// reference, so it is the one that destroys the captured object. Same hazard
  /// the caller-owned `doomed` local fixes for clear/set/shutdown.
  struct HandlerCopyDropper
  {
    // Explicit ctor for the same reason as FrozenReleaser: a user-declared (even
    // deleted) constructor stops this being an aggregate in C++20.
    explicit HandlerCopyDropper(std::optional<ExternalHandler> &slot) : _slot(slot) {}
    ~HandlerCopyDropper()
    {
      // Implicitly noexcept, and _slot.reset() runs USER capture destructors. If
      // one of those throws (e.g. it logs and the sink throws), letting it escape
      // would std::terminate and erase the diagnosis.
      try
      {
        _slot.reset();
      }
      catch (...)
      {
      }
    }
    HandlerCopyDropper(const HandlerCopyDropper &) = delete;
    HandlerCopyDropper &operator=(const HandlerCopyDropper &) = delete;

  private:
    std::optional<ExternalHandler> &_slot;
  };

  /// \brief Deliver ONE rawQueue entry to the external handler outside
  /// `data.mutex`. Precondition: `lock` HELD. Returns false — with the lock still
  /// held and nothing delivered — when the queue is empty or the gate is closed.
  ///
  /// The gate check, the three capture copies, and the in-flight increment inside
  /// runHandlerUnlocked form ONE indivisible critical section under the still-held
  /// lock: a tear-out (clear/setExternalHandler) can null the gate the moment the
  /// lock is released, so everything the invocation needs must be copied first.
  /// This is the invariant the whole tear-out drain rests on, which is why the two
  /// drain sites (flush() and runWorker()) share this one implementation rather
  /// than each keeping a copy.
  ///
  /// handlerReentryDepth()==0 gates the dispatch (as at every other dispatch site):
  /// a handler that itself calls flush() must not re-invoke the handler on the
  /// already-queued entries (unbounded recursion, O(backlog) stack frames); those
  /// entries are left for the outer flush()/worker running at depth 0.
  ///
  /// A handler exception propagates to the caller with the lock RE-ACQUIRED and
  /// inflight already decremented (runHandlerUnlocked guarantees both). Callers
  /// differ only in policy: flush() propagates it, runWorker() swallows and
  /// continues.
  static bool deliverOneRawEntryLocked(std::unique_lock<std::mutex> &lock, LoggerData &data)
  {
    if (data.rawQueue.empty() || !data.useExternalHandler || !data.externalHandler ||
        handlerReentryDepth() != 0)
    {
      return false;
    }

    // Named locals, NOT structured bindings: the lambda below captures them, and
    // capturing a structured binding is ill-formed in C++17 (only allowed from
    // C++20, P1091R3 — GCC accepts it silently, Clang warns, and it is an error
    // under -pedantic-errors).
    const Level level = data.rawQueue.front().first;
    std::string rawMessage = std::move(data.rawQueue.front().second);
    data.rawQueue.pop();

    auto segments = data._compiledFormat;
    auto timestampFmt = data.timestampFormat;
    std::optional<ExternalHandler> handler(data.externalHandler);

    runHandlerUnlocked(lock, data,
                       [&] {
                         formatAndInvokeRawHandler(level, rawMessage, segments, timestampFmt,
                                                   handler);
                       });
    return true;
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

public:
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
      std::optional<ExternalHandler> handler(data.externalHandler);
      runHandlerUnlocked(lock, data,
                         [&]
                         {
                           HandlerInvocationScope inv;          // destroyed LAST
                           HandlerCopyDropper dropper(handler); // destroyed at depth 1
                           (*handler)(level, output, message);
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

      // Process external handler queue. Unlike flush(), the worker SWALLOWS a
      // handler exception and keeps draining — a throwing sink must not terminate
      // the worker. (On normal return AND on rethrow, deliverOneRawEntryLocked has
      // already re-acquired the lock and decremented inflight, so the catch
      // clauses must NOT re-lock.)
      bool delivered = true;
      while (delivered)
      {
        std::exception_ptr handlerError;
        try
        {
          delivered = deliverOneRawEntryLocked(lock, data);
        }
        catch (...)
        {
          // `delivered` keeps its prior value (true), so the drain continues.
          handlerError = std::current_exception();
        }
        if (handlerError)
        {
          reportAndReleaseUnlocked(lock, handlerError, "external handler threw");
        }
      }

      // Process normal logging queue. Guarded like the handler drain above: this
      // path reaches rotateLogFileIfNeeded() (filesystem_error) and stream writes,
      // and an escape from runWorker is an uncaught exception on a std::thread —
      // std::terminate. The exit publication below must still run, so the guard
      // wraps only the drain.
      std::exception_ptr sinkError;
      try
      {
        drainNormalQueueLocked(data);
      }
      catch (...)
      {
        sinkError = std::current_exception();
      }
      if (sinkError)
      {
        reportAndReleaseUnlocked(lock, sinkError, "sink threw in the worker drain");
      }

      if (data.exit)
      {
        // LAST action, still under the lock: publish that this worker is done so
        // a teardown that could not join it (it detached, or the thread object was
        // already moved out) can wait for it before destroying LoggerData.
        data.workerRunning = false;
        data.workerThreadId = std::thread::id{};
        data.externalHandlerDone.notify_all();
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