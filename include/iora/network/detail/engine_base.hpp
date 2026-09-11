#pragma once
#ifndef __linux__
#error "Linux-only (epoll/eventfd/timerfd)"
#endif

#include "iora/core/buffer_view.hpp"
#include "iora/network/transport_types.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace iora
{
namespace network
{
namespace detail
{

class EngineBase;

/// \brief Shutdown/lifetime gate for cross-thread posts from the off-thread
///        name-resolution continuation (see name_resolver.hpp).
///
/// A resolver continuation runs on a blockingIoPool() thread and must post the
/// resume closure back onto the engine's I/O thread — but the engine may have
/// been torn down meanwhile. The continuation captures a shared_ptr copy of this
/// gate and posts under \c m iff \c closed is false. The DERIVED engine's
/// shutdownDrain sets closed=true + engine=nullptr under \c m before the engine's
/// members die; start() RE-CREATES a fresh gate before the loop, so a stale
/// continuation keeps its OLD gate (closed) and drops. \c closed and \c engine
/// are always set together, so !closed implies engine is alive.
///
/// LOCK ORDERING (HR-2): \c m is acquired STRICTLY OUTSIDE the engine's command
/// mutex, and NO user-facing callback runs while \c m is held (#13/#14).
struct EnginePostGate
{
  std::mutex m;
  bool closed{false};
  EngineBase *engine{nullptr};
};

/// \brief Abstract engine interface — owned by Transport, never by consumers.
///
/// **Hard requirement on connect():** connect() MUST only enqueue a command
/// for the I/O thread to process asynchronously. It MUST NOT perform any
/// synchronous I/O, DNS resolution, or callback invocation. This is because
/// Transport::connectSync() relies on the following ordering:
///   1. engine->connect() returns a SessionId (command enqueued, not processed)
///   2. caller registers the SessionId in pendingConnects
///   3. I/O thread processes the command and fires onConnect/onClose
///
/// If connect() were to process synchronously (e.g., fire onConnect before
/// returning), step 2 would not yet have run, and connectSync would miss the
/// notification — hanging forever. Every EngineBase implementation must
/// preserve this enqueue-only contract.
class EngineBase
{
public:
  virtual ~EngineBase() = default;

  struct Callbacks
  {
    std::function<void(SessionId, const TransportAddress &)> onAccept;
    std::function<void(SessionId, const TransportAddress &)> onConnect;
    std::function<void(SessionId, iora::core::BufferView, std::chrono::steady_clock::time_point)>
      onData;
    std::function<void(SessionId, const TransportErrorInfo &)> onClose;
    std::function<void(TransportError, const std::string &)> onError;
  };

  // Lifecycle
  virtual StartResult start() = 0;
  virtual void stop() = 0;
  virtual bool isRunning() const = 0;
  virtual TransportErrorInfo lastError() const = 0;

  // Connection management
  virtual ListenResult addListener(const std::string &bindIp, std::uint16_t port,
                                   TlsMode tlsMode) = 0;

  /// \brief Initiate an outbound connection (async) with per-connection TLS
  /// client identity options — the PRIMITIVE.
  ///
  /// MUST only enqueue a command — never process synchronously.
  /// See class-level documentation for the ordering invariant.
  /// \param opts per-connection TLS client identity (verifyName + hostflags);
  ///   default-constructed => no SNI/identity override (legacy behavior).
  virtual ConnectResult connect(const std::string &host, std::uint16_t port,
                                TlsMode tlsMode, const TlsClientOptions &opts) = 0;

  /// \brief Legacy 3-arg connect — non-pure default delegating to the primitive
  /// with empty options (so no implementor is forced to reimplement it).
  ConnectResult connect(const std::string &host, std::uint16_t port, TlsMode tlsMode)
  {
    return connect(host, port, tlsMode, TlsClientOptions{});
  }
  virtual ConnectResult connectViaListener(ListenerId lid, const std::string &host,
                                           std::uint16_t port) = 0;
  virtual bool close(SessionId sid) = 0;

  // Data operations (raw pointer — Transport wraps in BufferView at the public API level)
  virtual bool send(SessionId sid, const void *data, std::size_t len) = 0;

  /// \brief Queue a send and report the outcome through \p cb (may be null).
  ///
  /// COMPLETION CONTRACT (CF-L6): a conforming engine MUST invoke \p cb either
  /// SYNCHRONOUSLY on the caller's thread, or — if it ever defers completion —
  /// before the I/O thread is joined in stop(). It MUST NEVER invoke \p cb after
  /// ~Impl. Callers (e.g. Transport::sendSync) capture raw state whose lifetime
  /// is bounded by the engine, so a completion firing after teardown is a
  /// use-after-free. Both current engines (TCP, UDP) complete SYNCHRONOUSLY on
  /// the caller's thread. The result reflects whether the send command was
  /// accepted by the I/O thread's queue (and, per CF-H1, that the session was
  /// known and not closed at enqueue time), NOT whether bytes reached the peer.
  virtual void sendAsync(SessionId sid, const void *data, std::size_t len,
                         SendCompleteCallback cb) = 0;

  // Callbacks (set once before start)
  virtual void setCallbacks(Callbacks cbs) = 0;

  // Stats
  virtual TransportStats getStats() const = 0;

  // Address introspection
  virtual TransportAddress getListenerAddress(ListenerId lid) const = 0;
  virtual TransportAddress getLocalAddress(SessionId sid) const = 0;
  virtual TransportAddress getRemoteAddress(SessionId sid) const = 0;

  // DSCP (per-session runtime change)
  virtual bool setDscp(SessionId sid, std::uint8_t dscp) = 0;

  /// \brief Enable or disable delivery of read (EPOLLIN) events for a session.
  ///
  /// When \p enabled is false the engine removes the session's fd from EPOLLIN so
  /// no further read events are delivered — avoiding the wasted recv() syscalls a
  /// ReadMode::Disabled session would otherwise incur only to drop the data at the
  /// transport callback. Re-enabling restores EPOLLIN. Returns true if the change
  /// was applied or scheduled on the I/O thread.
  /// \note For a shared-socket engine (UDP, where many virtual sessions share one
  ///   socket) a per-session EPOLLIN removal is not possible, so this is a no-op
  ///   that returns false.
  virtual bool setReadEnabled(SessionId sid, bool enabled) = 0;

  // I/O thread identification (for deadlock detection in sync operations)
  virtual std::thread::id getIoThreadId() const = 0;

  /// \brief Race-free "am I on the engine's I/O thread?" check.
  ///
  /// Reads an atomic thread-id stamped at loop entry and reset at loop exit
  /// (see stampIoThread()/clearIoThread(), called by each concrete engine's
  /// loop). This is deliberately DISTINCT from getIoThreadId():
  ///  - getIoThreadId() returns _loop.get_id() on the raw std::thread; it goes
  ///    to the default id immediately on detachForTermination() and is relied on
  ///    for exactly that null-after-detach behavior by shutdownDrain and the
  ///    sync-operation deadlock guards. It must NOT change.
  ///  - isOnIoThread() reads the atomic, which is safe to call from ANY thread
  ///    concurrently with start()/stop() (reading the raw std::thread would be a
  ///    data race). Used by higher layers (Transport::isOnIoThread, and iora_sip
  ///    transport-lifecycle refusal) to detect I/O-thread re-entry.
  /// Relaxed ordering suffices: the atomic is only ever equality-compared to
  /// this_thread::get_id() and publishes no companion data.
  bool isOnIoThread() const noexcept
  {
    return _ioThreadId.load(std::memory_order_relaxed) == std::this_thread::get_id();
  }

  // Emergency detach for destruction from I/O thread.
  // Sets _running=false and detaches the I/O thread so that the engine's
  // destructor doesn't deadlock trying to join the current thread.
  virtual void detachForTermination() = 0;

  // Deferred self-destruction (for Transport destroyed from within its own
  // I/O-thread callback). Registers a deleter that the detached I/O thread runs
  // in its post-loop() epilogue, AFTER all in-flight dispatch has unwound — so
  // freeing the owning object (which contains this engine) does not occur under
  // the engine's own running stack frame. MUST be called ONLY on the I/O thread,
  // before detachForTermination(); the deleter and its read are same-thread, so
  // no synchronization is used.
  virtual void scheduleSelfDestruct(std::function<void()> deleter) = 0;

  /// \brief Post \p fn to run on the engine's I/O thread. ALWAYS posts — never
  /// runs \p fn inline, even if called on the I/O thread.
  ///
  /// PUBLIC because the off-thread name-resolution continuation reaches it
  /// through an EnginePostGate::engine (an EngineBase*), mirroring the public
  /// scheduleSelfDestruct. Each concrete engine wraps \p fn into its own
  /// RunOnIo command variant and enqueues via a NOEXCEPT, callback-free path:
  /// on allocation failure it returns false and fires NO user callback (a
  /// dropped resolve post is backstopped by the resolve-timeout). Returns true
  /// iff the command was queued.
  virtual bool runOnIoThread(std::function<void()> fn) noexcept = 0;

protected:
  /// \brief Initializes the post gate with engine==this. start() re-creates it
  /// before the loop (tracker 2026-09-06-4 task-2.2/4.4); this initial gate
  /// covers the pre-start window.
  EngineBase() : _postGuard(std::make_shared<EnginePostGate>()) { _postGuard->engine = this; }

  /// \brief Stamp the current thread as the I/O thread. Call FIRST-THING in the
  /// concrete engine's loop thread, before any dispatch, so isOnIoThread() is
  /// valid for the whole loop lifetime.
  void stampIoThread() noexcept
  {
    _ioThreadId.store(std::this_thread::get_id(), std::memory_order_relaxed);
  }

  /// \brief Clear the I/O-thread stamp. Call at loop exit, AFTER loop()/drain
  /// has unwound and BEFORE the self-destruct deleter runs (the deleter may free
  /// the owning object, after which touching _ioThreadId would be a UAF). Reset
  /// to the default id so isOnIoThread() correctly returns false post-detach and
  /// never yields a recycled-thread-id false positive.
  void clearIoThread() noexcept
  {
    _ioThreadId.store(std::thread::id{}, std::memory_order_relaxed);
  }

  /// \brief Shared post gate captured by resolver continuations. Re-created in
  /// each derived engine's start() before the loop; closed (closed=true,
  /// engine=nullptr under _postGuard->m) in shutdownDrain before members die.
  /// See EnginePostGate. Protected: derived start()/shutdownDrain manage it.
  std::shared_ptr<EnginePostGate> _postGuard;

private:
  // Published I/O-thread identity for isOnIoThread(). std::thread::id is
  // trivially copyable, so std::atomic<std::thread::id> is lock-free on Linux
  // (id wraps pthread_t). Default-constructed (== no I/O thread) until stamped.
  std::atomic<std::thread::id> _ioThreadId{};
};

} // namespace detail
} // namespace network
} // namespace iora
