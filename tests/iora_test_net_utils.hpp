#pragma once

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <string>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>

namespace testnet
{

/// \brief Ignore SIGPIPE for the whole test PROCESS (sigaction, SIG_IGN).
///
/// A test binary that runs raw OpenSSL (SSL_write/SSL_shutdown) on its OWN threads is
/// exposed to a process-killing SIGPIPE when a peer closes mid-write: the iora engine
/// blocks SIGPIPE only on ITS I/O thread (pthread_sigmask), which does not cover the
/// harness's bare-OpenSSL threads. A test binary owns its process, so ignoring the
/// disposition here is legitimate (this is NOT done in library code).
///
/// Disposition (process-global, covers every thread regardless of when created) is used
/// rather than a pthread_sigmask (per-thread, inherited only by later-created threads,
/// and it would slip past a SIG_DFL-at-entry assertion). Call ONCE before any harness
/// thread is spawned (e.g. a Catch2 testRunStarting listener). Must NOT be a static
/// initializer: that would silently install it in every TU that includes this header,
/// including the engine-guard lock binary that needs SIGPIPE at SIG_DFL.
inline void ignoreSigpipeForTestProcess()
{
  struct sigaction sa{};
  sa.sa_handler = SIG_IGN;
  ::sigaction(SIGPIPE, &sa, nullptr);
}

/// \brief An RAII file descriptor: closes on scope exit, so a REQUIRE that throws
/// mid-setup cannot leak the socket. Moving transfers ownership (source left empty).
class ScopedFd
{
public:
  ScopedFd() = default;
  explicit ScopedFd(int fd) : _fd(fd) {}
  ~ScopedFd()
  {
    if (_fd >= 0)
    {
      ::close(_fd);
    }
  }
  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;
  ScopedFd(ScopedFd &&o) noexcept : _fd(o._fd) { o._fd = -1; }
  ScopedFd &operator=(ScopedFd &&o) noexcept
  {
    if (this != &o)
    {
      if (_fd >= 0)
      {
        ::close(_fd);
      }
      _fd = o._fd;
      o._fd = -1;
    }
    return *this;
  }
  int get() const noexcept { return _fd; }

private:
  int _fd{-1};
};

/// \brief Bind a fresh OS-assigned port on 127.0.0.1 for `sockType` and return the
/// still-bound socket (RAII) plus the port. SO_REUSEADDR reduces the TOCTOU race with
/// parallel tests. The one v4-ephemeral-bind pattern shared by getFreePort,
/// RefusingEndpoint and bindDualLoopback.
inline ScopedFd bindLoopbackV4Ephemeral(int sockType, std::uint16_t &port)
{
  ScopedFd fd{::socket(AF_INET, sockType, 0)};
  REQUIRE(fd.get() >= 0);
  int reuse = 1;
  ::setsockopt(fd.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  REQUIRE(::bind(fd.get(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
  socklen_t len = sizeof(addr);
  REQUIRE(::getsockname(fd.get(), reinterpret_cast<sockaddr *>(&addr), &len) == 0);
  port = ntohs(addr.sin_port);
  return fd;
}

/// \brief Get a free port for `sockType` (SOCK_STREAM or SOCK_DGRAM), assigned by the OS.
/// Shared core for getFreePortTCP/getFreePortUDP (tracker 2026-09-14-4).
inline std::uint16_t getFreePort(int sockType)
{
  std::uint16_t port = 0;
  ScopedFd fd = bindLoopbackV4Ephemeral(sockType, port); // closes on return
  return port;
}

/// \brief Get a free TCP port, assigned by the OS.
inline std::uint16_t getFreePortTCP()
{
  return getFreePort(SOCK_STREAM);
}

/// \brief Get a free UDP port, assigned by the OS.
inline std::uint16_t getFreePortUDP()
{
  return getFreePort(SOCK_DGRAM);
}

/// \brief Get a port that is free for BOTH UDP and TCP on INADDR_ANY, for a server
/// that binds the same port on both protocols (MockDnsServer). Call it only inside a
/// running test: it asserts.
///
/// Socket-option discipline: the UDP probe sets NO SO_REUSEADDR (two UDP sockets that
/// both set it may share a port, so a probe with it cannot see a peer holder that also
/// set it). The TCP probe sets SO_REUSEADDR, like MockDnsServer, so a TIME_WAIT port
/// passes while a listening holder still conflicts. Both probes close before return,
/// leaving the same accepted probe-then-bind gap as getFreePort.
///
/// errno discipline: retry only on EADDRINUSE at the TCP bind; any other errno fails
/// loudly with strerror.
inline std::uint16_t getFreePortUdpTcp()
{
  for (int attempt = 0; attempt < 50; ++attempt)
  {
    ScopedFd udp{::socket(AF_INET, SOCK_DGRAM, 0)};
    REQUIRE(udp.get() >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    if (::bind(udp.get(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
    {
      FAIL("bind(UDP INADDR_ANY:0) failed: " << std::strerror(errno));
    }
    socklen_t len = sizeof(addr);
    REQUIRE(::getsockname(udp.get(), reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    const std::uint16_t port = ntohs(addr.sin_port);

    ScopedFd tcp{::socket(AF_INET, SOCK_STREAM, 0)};
    REQUIRE(tcp.get() >= 0);
    int reuse = 1;
    ::setsockopt(tcp.get(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (::bind(tcp.get(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0)
    {
      return port; // udp and tcp close here
    }
    const int e = errno;
    if (e != EADDRINUSE)
    {
      FAIL("bind(TCP INADDR_ANY) failed with an unexpected errno: " << std::strerror(e));
    }
    // EADDRINUSE on TCP: both close here; pick a fresh port, retry.
  }
  FAIL("no port free on both UDP and TCP after 50 attempts");
  return 0;
}

// ── Dual-family loopback helpers (tracker 2026-09-25-15) ─────────────────────
// A test that binds a listener on 127.0.0.1 but connects to the NAME "localhost"
// is environment-fragile: glibc AI_ADDRCONFIG does NOT count the loopback address,
// so once the host holds a GLOBAL IPv6 address, getaddrinfo("localhost") returns
// ::1 first and the connect targets a family nothing listens on. These helpers bind
// BOTH loopback families on one port so the connect lands whichever family resolves
// first. See the tracker's root_cause + helper_plan.

/// \brief Families `name` resolves to under the engines' resolve hints
/// (AF_UNSPEC|AI_ADDRCONFIG + matching sockType/protocol). The one getaddrinfo
/// boilerplate shared by firstResolvedFamily + ipv6OnlyNameAvailable so the hints
/// cannot drift apart. `first` is AF_UNSPEC when `name` does not resolve.
struct ResolvedFamilies
{
  bool hasV4{false};
  bool hasV6{false};
  int first{AF_UNSPEC};
};
inline ResolvedFamilies resolveFamilies(const char *name, int sockType)
{
  ::addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = sockType;
  // Match the engines' hints exactly (tcp_engine.hpp / udp_engine.hpp set ai_protocol).
  hints.ai_protocol = (sockType == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP;
  hints.ai_flags = AI_ADDRCONFIG;
  ::addrinfo *res = nullptr;
  ResolvedFamilies out{};
  if (::getaddrinfo(name, "0", &hints, &res) != 0 || res == nullptr)
  {
    return out;
  }
  out.first = res->ai_family;
  for (::addrinfo *ai = res; ai != nullptr; ai = ai->ai_next)
  {
    if (ai->ai_family == AF_INET)
    {
      out.hasV4 = true;
    }
    else if (ai->ai_family == AF_INET6)
    {
      out.hasV6 = true;
    }
  }
  ::freeaddrinfo(res);
  return out;
}

/// \brief Family glibc returns FIRST for `name` (AF_INET6, AF_INET, or AF_UNSPEC if
/// unresolvable). Used to GATE a host-conditional test — never to pin a listener
/// family (that would reintroduce the TOCTOU this file exists to kill).
inline int firstResolvedFamily(const char *name, int sockType)
{
  return resolveFamilies(name, sockType).first;
}

/// \brief True iff `name` resolves to an IPv6-ONLY address chain — the precondition
/// for an AF-mismatch case against an IPv4-only listener.
inline bool ipv6OnlyNameAvailable(const char *name, int sockType)
{
  ResolvedFamilies r = resolveFamilies(name, sockType);
  return r.hasV6 && !r.hasV4;
}

/// \brief A port bound (not listening) on BOTH loopback families, with the sockets
/// held open. The single primitive behind probeDualLoopbackPort AND
/// DualRefusingEndpoint, so their retry/ordering/errno rules can never drift apart.
/// `v6` is -1 when ::1 is unavailable on this host (then it is a v4-only binding).
struct DualLoopbackBinding
{
  ScopedFd v4;
  ScopedFd v6; // -1 if ::1 unavailable
  std::uint16_t port{0};
  bool v6Available() const { return v6.get() >= 0; }
};

/// \brief Bind a fresh port on 127.0.0.1 and ::1 using RAW sockets (never the engine:
/// a failed engine addListener fires the user's onError and perturbs fixtures). The
/// sockets are held bound-not-listening so a connect gets ECONNREFUSED. v4 first
/// (ephemeral), then ::1 at the same port.
///
/// Socket-option discipline (matches what the engine listeners do, so a successful
/// probe predicts a successful engine bind): the v4 probe sets SO_REUSEADDR (the engine's
/// v4 listener sets REUSEADDR+REUSEPORT); the ::1 probe sets NO reuse option (neither the
/// TCP v6 listener nor any UDP listener sets one), so the probe does not falsely succeed
/// where the engine would collide.
///
/// errno discipline: retry ONLY on EADDRINUSE at ::1; EADDRNOTAVAIL/EAFNOSUPPORT (or
/// EAFNOSUPPORT/EPROTONOSUPPORT from socket()) => ::1 unavailable, v4-only; any other
/// errno fails loudly with strerror rather than silently exhausting all attempts.
inline DualLoopbackBinding bindDualLoopback(int sockType)
{
  for (int attempt = 0; attempt < 50; ++attempt)
  {
    DualLoopbackBinding b;
    b.v4 = bindLoopbackV4Ephemeral(sockType, b.port);

    // ::1 at the SAME port. A specific ::1 bind never conflicts with 127.0.0.1
    // (IPV6_V6ONLY is irrelevant for a non-wildcard address).
    ScopedFd v6{::socket(AF_INET6, sockType, 0)};
    if (v6.get() < 0)
    {
      if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
      {
        return b; // v4-only: no IPv6 on this host
      }
      FAIL("socket(AF_INET6) failed: " << std::strerror(errno));
    }
    // No reuse option on the ::1 probe — match the engine's v6/UDP listeners.
    sockaddr_in6 a6{};
    a6.sin6_family = AF_INET6;
    a6.sin6_addr = in6addr_loopback;
    a6.sin6_port = htons(b.port);
    if (::bind(v6.get(), reinterpret_cast<sockaddr *>(&a6), sizeof(a6)) == 0)
    {
      b.v6 = std::move(v6);
      return b; // dual-free
    }
    int e = errno;
    if (e == EADDRNOTAVAIL || e == EAFNOSUPPORT)
    {
      return b; // ::1 not bindable on this host -> v4-only
    }
    if (e != EADDRINUSE)
    {
      FAIL("bind(::1) failed with an unexpected errno: " << std::strerror(e));
    }
    // EADDRINUSE on ::1:port — b (v4) and v6 close here; pick a fresh port, retry.
  }
  FAIL("no dual-free loopback port after 50 attempts");
  return {};
}

/// \brief Find a port free on BOTH 127.0.0.1 and ::1 for `sockType`, closing the probe
/// sockets before returning. Sets `v6Available=false` when ::1 is unavailable (v4-only).
inline std::uint16_t probeDualLoopbackPort(int sockType, bool &v6Available)
{
  DualLoopbackBinding b = bindDualLoopback(sockType);
  v6Available = b.v6Available();
  return b.port; // b's ScopedFds close here
}

/// \brief Bind loopback listeners on BOTH families (::1 FIRST, then 127.0.0.1) on a
/// single port via `engine.addListener(host, port, tls)`, and return that port, so a
/// connect to the NAME "localhost" lands regardless of which family resolves first.
/// `tls` is applied to both listeners. `*v6Bound` (optional) = a ::1 listener is up.
///
/// A ::1-capable host ALWAYS gets a ::1 listener — this is what makes the dual-bind
/// guards meaningful. The raw probe says whether ::1 is bindable; if it is but the
/// engine ::1 bind then loses a port race, we retry a fresh port BEFORE any v4 listener
/// exists (nothing to undo) and, after a few tries, FAIL loudly naming a likely ::1
/// listener regression — we never silently degrade a ::1-capable host to v4-only. So on
/// return `*v6Bound == (the probe found ::1 bindable)`; a ::1-path regression surfaces
/// as the FAIL here (in ANY caller on a ::1-capable host), not as a quiet v4-only pass.
/// (Each failed engine ::1 bind fires the fixture's onError — the reason the port is
/// chosen by a RAW probe, so this engine-bind retry is rare.)
///
/// `sockType` MUST match the engine's transport (SOCK_STREAM for TcpEngine, SOCK_DGRAM
/// for UdpEngine) — it selects the port-probe family. A static_assert cannot enforce
/// this without including the iora engine headers here (this util header is kept
/// iora-include-free), so the contract is the caller's; a mismatch probes the wrong port
/// space and the engine addListener below would then fail its REQUIRE.
template <typename Engine, typename TlsModeT>
std::uint16_t addLoopbackListeners(Engine &engine, int sockType, TlsModeT tls,
                                   bool *v6Bound = nullptr)
{
  constexpr int kV6RaceRetries = 3; // a genuine port race is rare; past this it is a regression
  for (int attempt = 0; attempt < kV6RaceRetries; ++attempt)
  {
    bool probeV6 = false;
    std::uint16_t port = probeDualLoopbackPort(sockType, probeV6);
    if (probeV6)
    {
      // ::1 FIRST: the v6 listener has no SO_REUSEPORT, so a lost race fails cleanly
      // with no v4 listener yet to undo. On that rare race, retry a fresh port.
      if (!engine.addListener("::1", port, tls).isOk())
      {
        continue;
      }
    }
    else
    {
      WARN("::1 unavailable on loopback — binding 127.0.0.1 only (port " << port << ")");
    }
    REQUIRE(engine.addListener("127.0.0.1", port, tls).isOk());
    if (v6Bound != nullptr)
    {
      *v6Bound = probeV6;
    }
    return port;
  }
  // The raw probe verified ::1 bindable on kV6RaceRetries fresh ports, yet the engine
  // refused a ::1 listener every time: a likely ::1-listener regression, not a race.
  FAIL("engine rejected a ::1 listener on " << kV6RaceRetries
       << " probe-verified ports — likely a ::1 listener regression, not a bind race");
  return 0;
}

/// \brief A TCP endpoint that is BOUND but NOT listening: a connect() to it gets
/// an immediate RST -> ECONNREFUSED, deterministically, on both standard Linux
/// AND WSL2. A truly-unbound loopback port instead black-holes the SYN in some
/// sandboxes (WSL2 mirrored networking swallows the RST), so connect() sits in
/// SYN-retry and only fails via a long connect-timeout — which is what made the
/// dead-port "connection refused" tests environment-dependent. Binding (but not
/// listening) makes the REFUSED outcome deterministic across platforms.
/// RAII: the ScopedFd holds the socket open for the endpoint's lifetime and closes it on
/// dtor, so declare the object at a scope that outlives the connect and its wait.
/// Non-copyable and non-movable so the bound port stays tied to one object for the
/// test's scope (ScopedFd would make a defaulted move safe; we simply don't want one).
class RefusingEndpoint
{
public:
  // Bind an ephemeral loopback port but DO NOT listen — the kernel RSTs connects to a
  // bound-not-listening port, yielding ECONNREFUSED rather than a black-holed timeout.
  // Shares bindLoopbackV4Ephemeral with getFreePort / bindDualLoopback.
  // NOTE: _port MUST be declared before _fd — _fd's initializer writes _port by
  // reference, so _port must already be alive (members init in declaration order).
  RefusingEndpoint() : _fd(bindLoopbackV4Ephemeral(SOCK_STREAM, _port)) {}

  RefusingEndpoint(const RefusingEndpoint &) = delete;
  RefusingEndpoint &operator=(const RefusingEndpoint &) = delete;
  RefusingEndpoint(RefusingEndpoint &&) = delete;
  RefusingEndpoint &operator=(RefusingEndpoint &&) = delete;

  std::uint16_t port() const { return _port; }

private:
  std::uint16_t _port{0}; // MUST precede _fd (see ctor note)
  ScopedFd _fd;
};

/// \brief A RefusingEndpoint that refuses on BOTH loopback families at one port: a
/// connect to the NAME "localhost":port() gets ECONNREFUSED whichever family
/// getaddrinfo returns first (see the dual-family rationale above). Binds-not-listens
/// on 127.0.0.1 AND ::1 (when available); on a host without ::1 it degrades to v4-only
/// (v6Bound()==false). Holds the two bound sockets open via bindDualLoopback (the same
/// primitive probeDualLoopbackPort uses, so the retry/ordering/errno rules cannot drift
/// and a throwing bind cannot leak an fd — RAII). Non-copyable / non-movable so the
/// bound port stays tied to one object for the test's scope. Used by named-host
/// terminal/refusal cases so they refuse for the INTENDED reason, not because nothing
/// happens to listen on ::1.
class DualRefusingEndpoint
{
public:
  DualRefusingEndpoint() : _binding(bindDualLoopback(SOCK_STREAM)) {}

  DualRefusingEndpoint(const DualRefusingEndpoint &) = delete;
  DualRefusingEndpoint &operator=(const DualRefusingEndpoint &) = delete;
  DualRefusingEndpoint(DualRefusingEndpoint &&) = delete;
  DualRefusingEndpoint &operator=(DualRefusingEndpoint &&) = delete;

  std::uint16_t port() const { return _binding.port; }
  bool v6Bound() const { return _binding.v6Available(); }

private:
  // bound-not-listening on both families -> the kernel RSTs a connect (ECONNREFUSED).
  DualLoopbackBinding _binding;
};

/// \brief Open a blocking loopback TCP socket to 127.0.0.1:`port`, apply an
/// `SO_RCVTIMEO` receive timeout, and connect. Returns the connected fd, or -1 on any
/// socket/connect failure (the fd is closed before -1 is returned). The shared prologue
/// for the raw-socket test helpers below (de-duplicated per the simplification review,
/// tracker 2026-09-14-4). The receive-timeout bound turns a close-handling regression
/// into a diagnosable failure instead of a CI hang for the recv-until-EOF callers.
inline int connectLoopbackTcp(int port, int rcvTimeoutSec = 15)
{
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    return -1;
  }
  struct timeval rcvTimeout{};
  rcvTimeout.tv_sec = rcvTimeoutSec;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcvTimeout, sizeof(rcvTimeout));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<std::uint16_t>(port));
  addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");
  if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
  {
    ::close(fd);
    return -1;
  }
  return fd;
}

/// \brief Send raw request bytes to a loopback TCP port and return the full raw
/// HTTP response (or "" on any socket error). Used where HttpClient's map API
/// cannot express the wire form — an OPTIONS preflight, or duplicate header
/// field-lines (RFC 9110 §5.3). Reads until the peer closes, so the request
/// SHOULD carry `Connection: close`. (Slice-B review L7: de-duplicated from the
/// jsonrpc gzip request/response tests, which each had a byte-identical copy.)
inline std::string rawHttpRequest(int port, const std::string &requestBytes)
{
  // Reads until EOF, relying on the server honoring "Connection: close".
  int fd = connectLoopbackTcp(port);
  if (fd < 0)
  {
    return "";
  }
  std::string out;
  if (::send(fd, requestBytes.data(), requestBytes.size(), 0) ==
      static_cast<ssize_t>(requestBytes.size()))
  {
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0)
    {
      out.append(buf, static_cast<std::size_t>(n));
    }
  }
  ::close(fd);
  return out;
}

/// \brief Connect to a loopback TCP port, send `payload`, then (if `halfClose`)
/// immediately `shutdown(SHUT_WR)` with NO intervening delay, and read the server's
/// reply. Returns the received bytes ("" if none).
///
/// Purpose (tracker 2026-09-14-4): pin iora's read-half-EOF => close contract. With
/// halfClose=true and no delay, the client FIN batches with the request into a single
/// server-side readAvail drain, so the server hits recv()==0 and closeNow() BEFORE the
/// (asynchronously enqueued) response drains — the response is dropped. A determinism
/// caveat the reviewers flagged: the shutdown MUST be back-to-back with the send (no
/// sleep), or the eventfd wakeup can flush the response before the FIN arrives and mask
/// the drop.
///
/// `halfClose=false` is the executable POSITIVE CONTROL: a normal full-duplex client
/// (no SHUT_WR) that reads the echo — proves the echo path works, so a drop under
/// halfClose is specifically the half-close, not a broken fixture. In that mode the
/// echo server keeps the session open, so the read STOPS once `payload.size()` bytes are
/// in hand rather than blocking on the 15s SO_RCVTIMEO waiting for an EOF that never
/// comes (per the cpp17 review); halfClose=true reads to EOF (the server closes).
inline std::string rawTcpHalfCloseExchange(int port, const std::string &payload,
                                           bool halfClose)
{
  int fd = connectLoopbackTcp(port);
  if (fd < 0)
  {
    return "";
  }
  std::string out;
  if (::send(fd, payload.data(), payload.size(), 0) ==
      static_cast<ssize_t>(payload.size()))
  {
    if (halfClose)
    {
      // Back-to-back with the send, NO delay (determinism — see doc above).
      ::shutdown(fd, SHUT_WR);
    }
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0)
    {
      out.append(buf, static_cast<std::size_t>(n));
      // Positive-control path (no half-close): the echo server never closes on its
      // own, so stop once the full echo is in hand instead of stalling to timeout.
      if (!halfClose && out.size() >= payload.size())
      {
        break;
      }
    }
  }
  ::close(fd);
  return out;
}

/// \brief Confirm a TLS test cert file is present/readable; WARN and return false if
/// not (so a TLS test can skip cleanly). The canonical fopen-probe for the raw-TLS test
/// helpers — the caller builds the path from IORA_TEST_RESOURCE_DIR and passes it in, so
/// this header need not reference that per-target macro. (Simplification review: shared
/// with the copy in iora_test_transport.cpp's tlsCertsAvailable.)
inline bool tlsCertFileReadable(const std::string &certFile)
{
  FILE *cf = std::fopen(certFile.c_str(), "r");
  if (cf == nullptr)
  {
    WARN("TLS certs not available at " << certFile << " — skipping TLS test");
    return false;
  }
  std::fclose(cf);
  return true;
}

} // namespace testnet

// RAII helper for epoll fd
class EpollHelper
{
public:
  EpollHelper() : epollFd_(epoll_create1(EPOLL_CLOEXEC))
  {
    if (epollFd_ < 0)
    {
      throw std::system_error(errno, std::system_category(), "epoll_create1 failed");
    }
  }

  ~EpollHelper()
  {
    if (epollFd_ >= 0)
    {
      close(epollFd_);
    }
  }

  int fd() const { return epollFd_; }

  void addFd(int fd, uint32_t events = EPOLLIN)
  {
    epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &ev) < 0)
    {
      throw std::system_error(errno, std::system_category(), "epoll_ctl ADD failed");
    }
  }

private:
  int epollFd_;
};

// RAII helper for eventfd
class EventFdHelper
{
public:
  EventFdHelper() : eventFd_(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))
  {
    if (eventFd_ < 0)
    {
      throw std::system_error(errno, std::system_category(), "eventfd failed");
    }
  }

  ~EventFdHelper()
  {
    if (eventFd_ >= 0)
    {
      close(eventFd_);
    }
  }

  int fd() const { return eventFd_; }

  void signal(uint64_t value = 1)
  {
    if (write(eventFd_, &value, sizeof(value)) != sizeof(value))
    {
      // Non-blocking write might fail if fd is full, that's okay
    }
  }

  void drain()
  {
    uint64_t value;
    while (read(eventFd_, &value, sizeof(value)) == sizeof(value))
    {
      // Keep draining
    }
  }

private:
  int eventFd_;
};
