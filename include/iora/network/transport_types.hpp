// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
#ifndef __linux__
#error "Linux-only (epoll/eventfd/timerfd)"
#endif

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace iora
{
namespace network
{

using SessionId = std::uint64_t;
using ListenerId = std::uint64_t;
using ByteBuffer = std::vector<std::uint8_t>;
using MonoClock = std::chrono::steady_clock;
using MonoTime = std::chrono::time_point<MonoClock>;

enum class Role
{
  ServerPeer,
  ClientConnected
};

enum class TlsMode
{
  None,
  Server,
  Client
};

enum class TransportError
{
  None = 0,
  Socket,
  Resolve,
  Bind,
  Listen,
  Accept,
  Connect,
  TLSHandshake,
  TLSIO,
  PeerClosed,
  WriteBackpressure,
  Config,
  GCClosed,
  Cancelled,
  Timeout,
  Unknown
};

struct IoResult
{
  bool ok{true};
  TransportError code{TransportError::None};
  std::string message;
  int sysErrno{0};
  int tlsError{0};

  static IoResult success() { return {true, TransportError::None, "", 0, 0}; }

  static IoResult failure(TransportError c, const std::string &m, int se = 0, int te = 0)
  {
    return {false, c, m, se, te};
  }
};

// Enhanced error reporting with severity and context
enum class ErrorSeverity
{
  Warning,
  Recoverable,
  Fatal
};

struct TransportEvent
{
  TransportError code{TransportError::None};
  ErrorSeverity severity{ErrorSeverity::Warning};
  std::string context;
  std::string details;
  SessionId sessionId{0};
  std::chrono::system_clock::time_point timestamp{std::chrono::system_clock::now()};
  int sysErrno{0};
  int tlsError{0};

  static TransportEvent warning(TransportError code, const std::string &ctx,
                                const std::string &details = "")
  {
    return {code, ErrorSeverity::Warning, ctx, details, 0, std::chrono::system_clock::now(), 0, 0};
  }

  static TransportEvent error(TransportError code, const std::string &ctx,
                              const std::string &details = "", int sysErr = 0)
  {
    return {code, ErrorSeverity::Recoverable,       ctx,    details,
            0,    std::chrono::system_clock::now(), sysErr, 0};
  }

  static TransportEvent fatal(TransportError code, const std::string &ctx,
                              const std::string &details = "", int sysErr = 0)
  {
    return {code, ErrorSeverity::Fatal, ctx, details, 0, std::chrono::system_clock::now(), sysErr,
            0};
  }
};

// Synchronous result for listener operations
struct ListenerResult
{
  ListenerId id{0};
  IoResult result;
  std::string bindAddress;

  static ListenerResult success(ListenerId lid, const std::string &addr)
  {
    return {lid, IoResult::success(), addr};
  }

  static ListenerResult failure(TransportError code, const std::string &msg, int sysErr = 0)
  {
    return {0, IoResult::failure(code, msg, sysErr), ""};
  }
};

} // namespace network
} // namespace iora