// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file tcp_connect_test_fixtures.hpp
/// \brief Shared TcpEngine connect-path fixtures (tracker 2026-09-24-1): sink
///        servers, a recording client, raw and full-accept-queue (blackhole)
///        listeners. Include after <catch2/catch.hpp>.
///
/// Skip policy: a section whose environment prerequisite is missing (the test
/// certificates, or a blackhole that cannot be built) WARNs and skips that section
/// only, via certsOrSkip()/fillOrSkip(); every other precondition is a REQUIRE.

#pragma once

#include "iora/network/detail/tcp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "resolve_stall_harness.hpp"
#include "tcp_engine_test_access.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace tcptest
{

using namespace std::chrono_literals;
using TcpEngine = iora::network::TcpEngine;
using TransportConfig = iora::network::TransportConfig;
using TransportAddress = iora::network::TransportAddress;
using TransportErrorInfo = iora::network::TransportErrorInfo;
using TransportError = iora::network::TransportError;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;
using SendResult = iora::network::SendResult;
using TA = iora::network::TcpEngineTestAccess;
using ConnectThrowPoint = TA::ConnectThrowPoint;

inline bool waitFor(const std::function<bool()> &cond, std::chrono::milliseconds timeout = 3000ms)
{
  return resolvetest::waitFor(cond, timeout);
}

inline bool testCerts(std::string &certFile, std::string &keyFile)
{
  certFile = std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_cert.pem";
  keyFile = std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_key.pem";
  return testnet::tlsCertFileReadable(certFile);
}

/// Skip-policy helper: true if the test certificates are readable, else WARN.
inline bool certsOrSkip(std::string &certFile, std::string &keyFile)
{
  if (testCerts(certFile, keyFile))
  {
    return true;
  }
  WARN("test TLS certificates not readable; skipping this section");
  return false;
}

inline std::size_t countOpenFds()
{
  std::size_t n = 0;
  DIR *d = ::opendir("/proc/self/fd");
  if (d == nullptr)
  {
    return 0;
  }
  while (::readdir(d) != nullptr)
  {
    ++n;
  }
  ::closedir(d);
  return n;
}

/// Run \p fn on the engine's I/O thread and wait for it (bounded). \p fn never
/// runs after this returns: on a timeout the closure is abandoned under the same
/// lock that guards the call, so a late closure is a no-op.
inline bool runOnIo(TcpEngine &tx, std::function<void()> fn)
{
  struct State
  {
    std::mutex m;
    bool abandoned{false};
    std::function<void()> fn;
    std::promise<void> done;
  };
  auto st = std::make_shared<State>();
  st->fn = std::move(fn);
  auto fut = st->done.get_future();
  iora::network::detail::EngineBase &base = tx;
  if (!base.runOnIoThread([st] {
        std::lock_guard<std::mutex> lk(st->m);
        if (st->abandoned)
        {
          return;
        }
        st->fn();
        st->done.set_value();
      }))
  {
    return false;
  }
  if (fut.wait_for(3s) == std::future_status::ready)
  {
    return true;
  }
  std::lock_guard<std::mutex> lk(st->m);
  if (fut.wait_for(0s) == std::future_status::ready)
  {
    return true;
  }
  st->abandoned = true;
  return false;
}

inline std::size_t pendingConnectCount(TcpEngine &tx)
{
  std::size_t n = static_cast<std::size_t>(-1);
  runOnIo(tx, [&] { n = TA::pendingConnectCount(tx); });
  return n;
}

/// Deterministic byte pattern (offset-dependent, not period-26 aligned).
inline std::uint8_t patternByte(std::size_t i)
{
  return static_cast<std::uint8_t>((i * 7u + i / 251u) & 0xffu);
}

inline std::string patternPayload(std::size_t offset, std::size_t n)
{
  std::string out(n, '\0');
  for (std::size_t i = 0; i < n; ++i)
  {
    out[i] = static_cast<char>(patternByte(offset + i));
  }
  return out;
}

/// accept() one pending connection on \p lfd within \p t; -1 if none.
inline int acceptWithin(int lfd, std::chrono::milliseconds t)
{
  pollfd p{lfd, POLLIN, 0};
  if (::poll(&p, 1, static_cast<int>(t.count())) != 1)
  {
    return -1;
  }
  return ::accept(lfd, nullptr, nullptr);
}

/// Plain or TLS TcpEngine listener that accumulates every received byte.
struct SinkServer
{
  TransportConfig cfg{};
  std::mutex m;
  std::string received;
  std::vector<TransportErrorInfo> closeInfos;
  std::atomic<int> accepted{0};
  std::atomic<int> closes{0};
  std::atomic<bool> throwOnData{false};
  std::atomic<bool> throwOnClose{false};
  std::uint16_t port{0};
  std::unique_ptr<TcpEngine> tx;

  explicit SinkServer(bool tls = false, const std::string &certFile = {},
                      const std::string &keyFile = {},
                      std::function<void(TransportConfig &)> tweak = nullptr)
  {
    if (tls)
    {
      cfg.serverTls.enabled = true;
      cfg.serverTls.defaultMode = TlsMode::Server;
      cfg.serverTls.certFile = certFile;
      cfg.serverTls.keyFile = keyFile;
    }
    if (tweak)
    {
      tweak(cfg);
    }
    tx = std::make_unique<TcpEngine>(cfg);
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onAccept = [this](SessionId, const TransportAddress &) { accepted++; };
    cbs.onData = [this](SessionId, iora::core::BufferView data, std::chrono::steady_clock::time_point)
    {
      {
        std::lock_guard<std::mutex> lk(m);
        received.append(reinterpret_cast<const char *>(data.data()), data.size());
      }
      if (throwOnData.load())
      {
        throw std::runtime_error("user onData throws");
      }
    };
    cbs.onClose = [this](SessionId, const TransportErrorInfo &e)
    {
      {
        std::lock_guard<std::mutex> lk(m);
        closeInfos.push_back(e);
      }
      closes++;
      if (throwOnClose.load())
      {
        throw std::runtime_error("user onClose throws");
      }
    };
    tx->setCallbacks(cbs);
    REQUIRE(tx->start().isOk());
    port = testnet::getFreePortTCP();
    REQUIRE(tx->addListener("127.0.0.1", port, tls ? TlsMode::Server : TlsMode::None).isOk());
  }

  ~SinkServer()
  {
    if (tx)
    {
      tx->stop();
    }
  }

  std::string data()
  {
    std::lock_guard<std::mutex> lk(m);
    return received;
  }

  std::vector<TransportErrorInfo> closeInfoList()
  {
    std::lock_guard<std::mutex> lk(m);
    return closeInfos;
  }
};

/// Client TcpEngine recording per-sid connect/close outcomes.
struct Client
{
  TransportConfig cfg{};
  std::mutex m;
  std::map<SessionId, int> closeCountBySid;
  std::map<SessionId, TransportErrorInfo> closeInfoBySid;
  std::map<SessionId, std::chrono::steady_clock::time_point> closeTimeBySid;
  std::atomic<int> connectCount{0};
  std::atomic<int> closeCount{0};
  std::atomic<int> errorCount{0};
  std::atomic<bool> throwOnClose{false};
  std::function<void(SessionId, const TransportErrorInfo &)> onCloseHook; // guarded by m
  std::vector<std::pair<TransportError, std::string>> errors;
  std::unique_ptr<TcpEngine> tx;

  explicit Client(bool tlsClient = false,
                  std::function<void(TransportConfig &)> tweak = nullptr,
                  std::function<std::unique_ptr<TcpEngine>(const TransportConfig &)> make = nullptr)
  {
    if (tlsClient)
    {
      cfg.clientTls.enabled = true;
      cfg.clientTls.defaultMode = TlsMode::Client;
      cfg.clientTls.verifyPeer = false;
    }
    if (tweak)
    {
      tweak(cfg);
    }
    tx = make ? make(cfg) : std::make_unique<TcpEngine>(cfg);
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onConnect = [this](SessionId, const TransportAddress &) { connectCount++; };
    cbs.onClose = [this](SessionId sid, const TransportErrorInfo &e)
    {
      std::function<void(SessionId, const TransportErrorInfo &)> hook;
      {
        std::lock_guard<std::mutex> lk(m);
        closeCountBySid[sid]++;
        closeInfoBySid[sid] = e;
        closeTimeBySid[sid] = std::chrono::steady_clock::now();
        hook = onCloseHook;
      }
      closeCount++;
      if (hook)
      {
        hook(sid, e);
      }
      if (throwOnClose.load())
      {
        throw std::runtime_error("user onClose throws");
      }
    };
    cbs.onError = [this](TransportError code, const std::string &msg)
    {
      {
        std::lock_guard<std::mutex> lk(m);
        errors.emplace_back(code, msg);
      }
      errorCount++;
    };
    tx->setCallbacks(cbs);
  }

  ~Client()
  {
    if (tx)
    {
      tx->stop();
    }
  }

  void setOnCloseHook(std::function<void(SessionId, const TransportErrorInfo &)> hook)
  {
    std::lock_guard<std::mutex> lk(m);
    onCloseHook = std::move(hook);
  }

  int closesFor(SessionId sid)
  {
    std::lock_guard<std::mutex> lk(m);
    auto it = closeCountBySid.find(sid);
    return it == closeCountBySid.end() ? 0 : it->second;
  }

  /// Stop the engine (drains every queued command and fires every pending
  /// terminal), then return the number of onClose calls \p sid received: a
  /// deterministic "exactly one" check with no fixed sleep.
  int stopAndCountCloses(SessionId sid)
  {
    tx->stop();
    return closesFor(sid);
  }

  TransportErrorInfo closeInfo(SessionId sid)
  {
    std::lock_guard<std::mutex> lk(m);
    return closeInfoBySid[sid];
  }

  bool hasError(TransportError code, const std::string &prefix)
  {
    std::lock_guard<std::mutex> lk(m);
    for (const auto &e : errors)
    {
      if (e.first == code && e.second.compare(0, prefix.size(), prefix) == 0)
      {
        return true;
      }
    }
    return false;
  }

  std::chrono::steady_clock::time_point closeTime(SessionId sid)
  {
    std::lock_guard<std::mutex> lk(m);
    return closeTimeBySid[sid];
  }
};

/// Raw loopback listener that never accepts (connections sit in its queue, so no
/// fd is created in this process by the peer side).
struct RawListener
{
  int fd{-1};
  std::uint16_t port{0};

  explicit RawListener(int backlog = 16)
  {
    fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    REQUIRE(fd >= 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    REQUIRE(::bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0);
    REQUIRE(::listen(fd, backlog) == 0);
    socklen_t l = sizeof(a);
    REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr *>(&a), &l) == 0);
    port = ntohs(a.sin_port);
  }

  ~RawListener()
  {
    if (fd >= 0)
    {
      ::close(fd);
    }
  }
};

/// Loopback listener with a FULL accept queue (backlog 0, pre-filled, never
/// accepts): a further SYN is dropped, so a connect to it stays in the TCP phase.
struct Blackhole
{
  RawListener lst{0};
  std::vector<int> fillers;

  static bool connectsWithin(int c, std::chrono::milliseconds t)
  {
    pollfd p{c, POLLOUT, 0};
    if (::poll(&p, 1, static_cast<int>(t.count())) <= 0)
    {
      return false;
    }
    int e = 0;
    socklen_t el = sizeof(e);
    ::getsockopt(c, SOL_SOCKET, SO_ERROR, &e, &el);
    sockaddr_storage ss{};
    socklen_t sl = sizeof(ss);
    return e == 0 && ::getpeername(c, reinterpret_cast<sockaddr *>(&ss), &sl) == 0;
  }

  /// Fill the queue; true once a probe connect is confirmed NOT established.
  bool fill()
  {
    for (int i = 0; i < 8; ++i)
    {
      int c = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (c < 0)
      {
        return false;
      }
      sockaddr_in a{};
      a.sin_family = AF_INET;
      a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      a.sin_port = htons(lst.port);
      (void)::connect(c, reinterpret_cast<sockaddr *>(&a), sizeof(a));
      if (connectsWithin(c, 300ms))
      {
        fillers.push_back(c);
        continue;
      }
      ::close(c);
      return !fillers.empty();
    }
    return false;
  }

  ~Blackhole()
  {
    for (int c : fillers)
    {
      ::close(c);
    }
  }
};

/// Skip-policy helper: true if \p bh was filled, else WARN.
inline bool fillOrSkip(Blackhole &bh)
{
  if (bh.fill())
  {
    return true;
  }
  WARN("could not build a full-accept-queue blackhole; skipping this section");
  return false;
}

} // namespace tcptest
