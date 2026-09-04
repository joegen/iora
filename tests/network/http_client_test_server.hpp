// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Shared raw-socket primitives for the HttpClient wire tests (tracker
// 2026-07-26-10 task-1.4 review, simplification M1). makeListener() and
// writeAll() were byte-identical copies across the http_client_* test files;
// this de-duplicates the accept/bind primitive and the send loop so a fix
// (EINTR retry, a bind diagnostic) lands once. The per-test SERVER CLASSES
// (CapturingServer / RawServer / MultiServer / SlowServer) deliberately stay in
// their own files — they model genuinely different behaviors.
#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <fcntl.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace iora
{
namespace test
{
namespace httpsrv
{

/// \brief Create a non-blocking listening socket bound to 127.0.0.1:port
/// (SO_REUSEADDR, backlog 16). Returns the fd, or -1 on any failure.
inline int makeListener(std::uint16_t port)
{
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    return -1;
  }
  int opt = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ::inet_addr("127.0.0.1");
  addr.sin_port = htons(port);
  if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
  {
    ::close(fd);
    return -1;
  }
  if (::listen(fd, 16) < 0)
  {
    ::close(fd);
    return -1;
  }
  int flags = ::fcntl(fd, F_GETFL, 0);
  ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  return fd;
}

/// \brief Send the whole buffer, stopping on the first short/failed write.
inline void writeAll(int fd, const std::string &data)
{
  std::size_t off = 0;
  while (off < data.size())
  {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n <= 0)
    {
      break;
    }
    off += static_cast<std::size_t>(n);
  }
}

} // namespace httpsrv
} // namespace test
} // namespace iora
