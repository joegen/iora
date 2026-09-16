#pragma once

#include <arpa/inet.h>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <system_error>
#include <thread>
#include <unistd.h>

namespace testnet
{

/// \brief Get a free port for `sockType` (SOCK_STREAM or SOCK_DGRAM). If minPort/maxPort
/// are 0, the OS assigns one; otherwise the first bindable port in [minPort,maxPort] is
/// returned. Sets SO_REUSEADDR to reduce the TOCTOU race with parallel tests. Shared
/// core for getFreePortTCP/getFreePortUDP (simplification review, tracker 2026-09-14-4).
inline std::uint16_t getFreePort(int sockType, std::uint16_t minPort = 0,
                                 std::uint16_t maxPort = 0)
{
  int fd = ::socket(AF_INET, sockType, 0);
  REQUIRE(fd >= 0);

  int reuse = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  if (minPort > 0 && maxPort >= minPort)
  {
    for (std::uint16_t p = minPort; p <= maxPort; ++p)
    {
      addr.sin_port = htons(p);
      if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0)
      {
        ::close(fd);
        return p;
      }
    }
    ::close(fd);
    REQUIRE(false); // No free port in range
    return 0;
  }

  addr.sin_port = 0;
  REQUIRE(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);

  socklen_t len = sizeof(addr);
  REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
  std::uint16_t port = ntohs(addr.sin_port);
  ::close(fd);
  return port;
}

/// \brief Get a free TCP port. If minPort/maxPort are 0, the OS assigns one.
inline std::uint16_t getFreePortTCP(std::uint16_t minPort = 0, std::uint16_t maxPort = 0)
{
  return getFreePort(SOCK_STREAM, minPort, maxPort);
}

/// \brief Get a free UDP port. If minPort/maxPort are 0, the OS assigns one.
inline std::uint16_t getFreePortUDP(std::uint16_t minPort = 0, std::uint16_t maxPort = 0)
{
  return getFreePort(SOCK_DGRAM, minPort, maxPort);
}

/// \brief A TCP endpoint that is BOUND but NOT listening: a connect() to it gets
/// an immediate RST -> ECONNREFUSED, deterministically, on both standard Linux
/// AND WSL2. A truly-unbound loopback port instead black-holes the SYN in some
/// sandboxes (WSL2 mirrored networking swallows the RST), so connect() sits in
/// SYN-retry and only fails via a long connect-timeout — which is what made the
/// dead-port "connection refused" tests environment-dependent. Binding (but not
/// listening) makes the REFUSED outcome deterministic across platforms.
/// RAII: the socket is held open for the endpoint's lifetime and closed on dtor,
/// so declare the object at a scope that outlives the connect and its wait.
/// Non-copyable AND non-movable: the trivial int fd must have exactly one owner
/// (a move would leave both objects closing the same fd -> double-close).
class RefusingEndpoint
{
public:
  RefusingEndpoint()
  {
    _fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(_fd >= 0);
    int reuse = 1;
    ::setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    REQUIRE(::bind(_fd, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) == 0);
    socklen_t len = sizeof(sa);
    REQUIRE(::getsockname(_fd, reinterpret_cast<sockaddr *>(&sa), &len) == 0);
    _port = ntohs(sa.sin_port);
    // Intentionally NO listen() — the kernel RSTs connects to a bound-not-listening
    // port, yielding ECONNREFUSED rather than a black-holed timeout.
  }

  ~RefusingEndpoint()
  {
    if (_fd >= 0)
    {
      ::close(_fd);
    }
  }

  RefusingEndpoint(const RefusingEndpoint &) = delete;
  RefusingEndpoint &operator=(const RefusingEndpoint &) = delete;
  RefusingEndpoint(RefusingEndpoint &&) = delete;
  RefusingEndpoint &operator=(RefusingEndpoint &&) = delete;

  std::uint16_t port() const { return _port; }

private:
  int _fd{-1};
  std::uint16_t _port{0};
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
