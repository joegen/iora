#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <system_error>
#include <unistd.h>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

namespace testnet
{

inline std::uint16_t getFreePortTCP()
{
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  REQUIRE(::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  socklen_t len = sizeof(addr);
  REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
  std::uint16_t port = ntohs(addr.sin_port);
  ::close(fd);
  return port;
}

inline std::uint16_t getFreePortUDP()
{
  int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  REQUIRE(fd >= 0);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  REQUIRE(::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);

  socklen_t len = sizeof(addr);
  REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0);
  std::uint16_t port = ntohs(addr.sin_port);
  ::close(fd);
  return port;
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
      throw std::system_error(errno, std::system_category(),
                              "epoll_create1 failed");
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
      throw std::system_error(errno, std::system_category(),
                              "epoll_ctl ADD failed");
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
