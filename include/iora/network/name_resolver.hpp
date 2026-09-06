// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file name_resolver.hpp
/// \brief Header-only, event-driven, non-blocking name resolution helper.
///
/// Moves named-host ::getaddrinfo OFF the epoll I/O thread onto the immortal,
/// hard-capped, reject-fast iora::core::blockingIoPool(). See
/// architecture/iora/transport_dns_resolve.json (components C1/C3).

#pragma once

#include "iora/core/thread_pool.hpp"

#include <functional>
#include <memory>
#include <netdb.h>
#include <string>
#include <utility>

namespace iora
{
namespace network
{

/// \brief Move-only RAII owner of a ::getaddrinfo result chain.
///
/// This is the SOLE ::freeaddrinfo owner on the resolve path: the destructor
/// frees the chain iff non-null, and the connect loop (connectFromAddrs) must
/// NEVER free — ownership is external to it (see arch designPrinciple #6). The
/// chain travels to the I/O thread wrapped in a std::shared_ptr<OwnedAddrInfo>
/// so it is freed exactly once when the last handle drops.
class OwnedAddrInfo
{
public:
  OwnedAddrInfo() noexcept = default;

  /// \brief Take ownership of a ::getaddrinfo result head (may be nullptr).
  explicit OwnedAddrInfo(::addrinfo *head) noexcept : _head(head) {}

  ~OwnedAddrInfo()
  {
    if (_head != nullptr)
    {
      ::freeaddrinfo(_head);
    }
  }

  OwnedAddrInfo(const OwnedAddrInfo &) = delete;
  OwnedAddrInfo &operator=(const OwnedAddrInfo &) = delete;

  OwnedAddrInfo(OwnedAddrInfo &&other) noexcept : _head(other._head) { other._head = nullptr; }

  OwnedAddrInfo &operator=(OwnedAddrInfo &&other) noexcept
  {
    if (this != &other)
    {
      if (_head != nullptr)
      {
        ::freeaddrinfo(_head);
      }
      _head = other._head;
      other._head = nullptr;
    }
    return *this;
  }

  /// \brief Borrow the owned chain head without transferring ownership.
  ::addrinfo *get() const noexcept { return _head; }

  /// \brief Relinquish ownership; the caller becomes responsible for freeing.
  ::addrinfo *release() noexcept
  {
    ::addrinfo *h = _head;
    _head = nullptr;
    return h;
  }

  /// \brief True iff a non-null chain is owned.
  explicit operator bool() const noexcept { return _head != nullptr; }

private:
  ::addrinfo *_head{nullptr};
};

/// \brief Reject-fast sentinel returned in ResolveResult::gaiCode when the
///        blockingIoPool() queue is full (local backpressure), so the resolve
///        never runs.
///
/// A named, NON-EAI negative constant, deliberately far from the glibc EAI_*
/// range (which occupies roughly [-11, -1]) so it can never collide with a real
/// ::getaddrinfo error code. sip-M4 (RESOLVED 2026-09-06): this is INTERNAL to
/// the resolve path — the engine collapses it to TransportError::Resolve at
/// onClose and it is not externally observable; the cross-boundary
/// saturation-vs-resolution distinction is deferred to the F2 tracker
/// (2026-09-06-3). Distinguished here only by a distinct message string, which
/// gives operators a distinguishable log line.
constexpr int RESOLVER_POOL_SATURATED = -1000000;

/// \brief Outcome of an asynchronous name resolution.
///
/// gaiCode is 0 on success (addrs holds the chain), a ::getaddrinfo EAI_* error
/// on resolver failure (addrs null), or RESOLVER_POOL_SATURATED on reject-fast
/// (addrs null). addrs is a shared_ptr so the resolved chain can be captured by
/// value into the I/O-thread resume closure and freed exactly once.
struct ResolveResult
{
  int gaiCode{0};
  std::shared_ptr<OwnedAddrInfo> addrs;
};

/// \brief Human-readable message for a ResolveResult::gaiCode.
///
/// Returns a distinct "resolver pool saturated" string for the reject-fast
/// sentinel (so a local-backpressure event is not logged as a getaddrinfo
/// failure), otherwise ::gai_strerror(gaiCode).
inline const char *resolveErrorMessage(int gaiCode) noexcept
{
  if (gaiCode == RESOLVER_POOL_SATURATED)
  {
    return "resolver pool saturated";
  }
  return ::gai_strerror(gaiCode);
}

/// \brief Resolve \p host / \p port off the caller's thread, delivering the
///        result to \p onComplete.
///
/// Dispatches ::getaddrinfo onto the immortal, hard-capped, reject-fast
/// iora::core::blockingIoPool() so it NEVER runs on an epoll I/O thread. On
/// success onComplete runs on a pool thread with {0, chain}; on a resolver
/// error with {EAI_*, nullptr}; on pool saturation (tryEnqueue==false)
/// onComplete runs INLINE on the caller's thread with
/// {RESOLVER_POOL_SATURATED, nullptr}.
///
/// The dispatched task captures ONLY host / port / hints / onComplete by value
/// (no reference, no this, no engine pointer) — the continuation must be safe
/// to run after the caller has moved on. \p hints is copied by value; the
/// caller sets only its scalar fields (ai_family / ai_socktype / ai_protocol /
/// ai_flags).
inline void resolveHostAsync(std::string host, std::string port, ::addrinfo hints,
                             std::function<void(ResolveResult)> onComplete)
{
  // Not mutable: c_str() is const and ::getaddrinfo takes a const addrinfo* for
  // hints, so the task is const-callable — required because ThreadPool wraps it
  // via std::bind (whose operator() is const).
  auto task = [host = std::move(host), port = std::move(port), hints, onComplete]
  {
    ::addrinfo *res = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0)
    {
      onComplete(ResolveResult{rc, nullptr});
      return;
    }
    onComplete(ResolveResult{0, std::make_shared<OwnedAddrInfo>(res)});
  };

  // tryEnqueue takes the task by value; on rejection it is destroyed there, so
  // the reject-fast path fires the ORIGINAL onComplete parameter (a live copy),
  // never the moved-from task.
  if (!iora::core::blockingIoPool().tryEnqueue(std::move(task)))
  {
    onComplete(ResolveResult{RESOLVER_POOL_SATURATED, nullptr});
  }
}

} // namespace network
} // namespace iora
