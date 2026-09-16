#pragma once
//
// Deterministic fd-reuse probe helpers (tracker 2026-09-15-3).
//
// The transport engines defer every getter-reachable teardown ::close until AFTER
// the owning session/listener has been removed from its map under the write lock,
// so a cross-thread getter (getLocalAddress / setDscp / getListenerAddress, all
// holding the shared lock) can never syscall on a closed/reused fd. That ordering
// is NOT sanitizer-visible (the fd field is never written across threads), so a
// "clean under TSan/ASan" assertion would be VACUOUS.
//
// These helpers make the ordering DETERMINISTICALLY testable. Each engine exposes
// a TEST-ONLY pre-::close seam (testSetPreCloseHook) invoked with the fd number
// immediately before each teardown ::close. In the seam we dup2() a bound SENTINEL
// socket onto that fd — forcing reuse without racing the allocator — and then call
// the under-lock getter:
//   * fixed ordering   -> the entry is already out of its map -> getter returns {}
//                         and never touches the sentinel;
//   * buggy ordering   -> the entry is still in the map -> the getter resolves the
//                         (now dup2'd) fd and reads the SENTINEL's address / mutates
//                         the SENTINEL's IP_TOS — an unmistakable foreign observation.
//
// The seam runs on the I/O thread, so it does NOT call any Catch2 macro; it records
// raw outcomes into atomics that the main thread asserts AFTER stop()+join (the
// thread-join edge publishes the writes). Mutation-verify each case by moving the
// ::close back BEFORE the erase/clear: the seam is bound to the ::close (it travels
// with it), so the probe then observes the sentinel and the case FAILS.

#include <catch2/catch.hpp>

#include "iora/network/transport_types.hpp"

#include <arpa/inet.h>
#include <atomic>
#include <cstdint>
#include <functional>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace fdreuse
{

/// \brief A bound loopback socket used as the fd-reuse sentinel. Constructed and
/// inspected on the MAIN thread (so its REQUIREs are safe); only dup2Onto() is
/// called from the I/O-thread seam, and that returns a bool rather than asserting.
class Sentinel
{
public:
  Sentinel()
  {
    _fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    REQUIRE(_fd >= 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    REQUIRE(::bind(_fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) == 0);
    socklen_t len = sizeof(sa);
    REQUIRE(::getsockname(_fd, reinterpret_cast<sockaddr *>(&sa), &len) == 0);
    _addr.host = "127.0.0.1";
    _addr.port = ntohs(sa.sin_port);
  }

  ~Sentinel()
  {
    if (_fd >= 0)
    {
      ::close(_fd);
    }
  }

  Sentinel(const Sentinel &) = delete;
  Sentinel &operator=(const Sentinel &) = delete;
  Sentinel(Sentinel &&) = delete;
  Sentinel &operator=(Sentinel &&) = delete;

  const iora::network::TransportAddress &addr() const { return _addr; }

  /// \brief dup2 the sentinel socket onto \p targetFd so getsockname(targetFd) now
  /// returns the sentinel's address. Called from the I/O-thread seam — returns the
  /// success bool instead of asserting (no Catch2 on the I/O thread).
  bool dup2Onto(int targetFd) const { return ::dup2(_fd, targetFd) == targetFd; }

  /// \brief The sentinel socket's current IP_TOS (0 unless setDscp mutated it via a
  /// buggy ordering). MAIN-THREAD only.
  int ipTos() const
  {
    int tos = -1;
    socklen_t len = sizeof(tos);
    REQUIRE(::getsockopt(_fd, IPPROTO_IP, IP_TOS, &tos, &len) == 0);
    return tos;
  }

private:
  int _fd{-1};
  iora::network::TransportAddress _addr{};
};

/// \brief Cross-thread probe state. The armed inputs are set by the main thread
/// BEFORE the teardown is triggered; the outputs are written by the I/O-thread
/// seam and read by the main thread AFTER stop()+join.
struct Probe
{
  // Armed by the main thread before triggering teardown (read by the seam):
  std::atomic<int> targetFd{-1}; ///< probe only this fd; -1 => any fd the seam sees

  // Written by the seam (I/O thread):
  std::atomic<int> fireCount{0};    ///< total teardown ::closes the seam observed
  std::atomic<int> targetFires{0};  ///< fires for the armed target fd
  std::atomic<bool> dup2Ok{false};  ///< the sentinel trap was installed
  std::atomic<bool> sawSentinel{false}; ///< a getter resolved the sentinel == BUG
  std::atomic<bool> getterEmpty{true};  ///< a getter returned {} (fixed ordering)
  std::atomic<bool> dscpApplied{false}; ///< setDscp() returned true == BUG
};

/// \brief Record a getter's TransportAddress outcome against the sentinel. Call
/// from the seam. \p a is empty ({}) under the fixed ordering.
inline void recordGetter(Probe &p, const Sentinel &s, const iora::network::TransportAddress &a)
{
  p.sawSentinel.store(a == s.addr(), std::memory_order_relaxed);
  p.getterEmpty.store(a.host.empty() && a.port == 0, std::memory_order_relaxed);
}

/// \brief Spin (release-acquire) until \p go is set — a barrier for launching a
/// worker as close as possible to a release point. Shared by both engines' race
/// tests (was duplicated verbatim in each).
inline void spinUntil(const std::atomic<bool> &go)
{
  while (!go.load(std::memory_order_acquire))
  {
    std::this_thread::yield();
  }
}

/// \brief Build a pre-::close seam hook for the deterministic fd-reuse tests. It
/// increments fireCount for every teardown ::close it sees, and — for the armed
/// target fd (probe.targetFd; -1 = any) — dup2()s the sentinel onto the fd, then
/// records \p getter()'s outcome (and optional \p also()'s bool, used by the
/// setDscp probe) into the probe. Factors out the identical bookkeeping the per-test
/// hooks all repeated; the getter/also closures are the only per-test-varying part.
/// Runs on the I/O thread: NO Catch2 macro, only atomic stores + engine getters.
inline std::function<void(int)> makeCloseHook(
  Probe &p, const Sentinel &s, std::function<iora::network::TransportAddress()> getter,
  std::function<bool()> also = {})
{
  return [&p, &s, getter = std::move(getter), also = std::move(also)](int fd)
  {
    p.fireCount.fetch_add(1);
    const int want = p.targetFd.load();
    if (want >= 0 && fd != want)
    {
      return;
    }
    p.targetFires.fetch_add(1);
    p.dup2Ok.store(s.dup2Onto(fd));
    recordGetter(p, s, getter());
    if (also)
    {
      p.dscpApplied.store(also());
    }
  };
}

} // namespace fdreuse
