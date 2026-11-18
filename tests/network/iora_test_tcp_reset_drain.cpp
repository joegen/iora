// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Read before reset close (architecture/iora/engine_session_id_and_reset_drain.json
// IP-2, rows IP-T2 and IP-T3). When a peer writes and then resets, the engine delivers
// the bytes that already arrived to onData before onClose; the close code stays
// PeerClosed with the SO_ERROR errno. A read-disabled session is not drained.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora_test_net_utils.hpp"
#include "network/tcp_connect_test_fixtures.hpp"
#include "network/tcp_engine_test_access.hpp"
#include "test_helpers.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace iora::network;
using namespace tcptest;
using namespace std::chrono_literals;
using TA = TcpEngineTestAccess;
using EngineBase = iora::network::detail::EngineBase;

namespace
{
constexpr std::size_t kPayload = 3000;

struct FilterState
{
  std::atomic<SessionId> target{0};
  std::atomic<int> changed{0};
  std::mutex m;
  std::vector<std::uint32_t> passed;
};

struct Recorder
{
  std::mutex m;
  std::vector<SessionId> accepted;
  std::string data;
  bool dataAfterClose{false};
  bool closed{false};
  TransportError closeCode{TransportError::Unknown};
  int closeErrno{0};
  unsigned long errPeekInClose{0};
  SessionId watched{0};
};

struct ResetServer
{
  TransportConfig cfg{};
  std::shared_ptr<Recorder> rec = std::make_shared<Recorder>();
  std::shared_ptr<FilterState> filter = std::make_shared<FilterState>();
  std::unique_ptr<TcpEngine> tx;
  std::uint16_t port{0};

  ResetServer(bool tls, const std::string &certFile, const std::string &keyFile)
  {
    if (tls)
    {
      cfg.serverTls.enabled = true;
      cfg.serverTls.defaultMode = TlsMode::Server;
      cfg.serverTls.certFile = certFile;
      cfg.serverTls.keyFile = keyFile;
    }
    REQUIRE(cfg.useEdgeTriggered);
    tx = std::make_unique<TcpEngine>(cfg);

    auto f = filter;
    TA::setSessionEventFilterHook(*tx,
                                  [f](SessionId sid, std::uint32_t ev) -> std::uint32_t
                                  {
                                    const SessionId t = f->target.load();
                                    if (t == 0 || sid != t)
                                    {
                                      return ev;
                                    }
                                    if ((ev & (EPOLLHUP | EPOLLERR)) != 0)
                                    {
                                      std::lock_guard<std::mutex> lk(f->m);
                                      f->passed.push_back(ev);
                                      return ev;
                                    }
                                    f->changed.fetch_add(1);
                                    return ev & ~static_cast<std::uint32_t>(EPOLLIN);
                                  });

    auto r = rec;
    EngineBase::Callbacks cbs{};
    cbs.onAccept = [r](SessionId sid, const TransportAddress &)
    {
      std::lock_guard<std::mutex> lk(r->m);
      r->accepted.push_back(sid);
    };
    cbs.onData = [r](SessionId sid, iora::core::BufferView bv,
                     std::chrono::steady_clock::time_point)
    {
      std::lock_guard<std::mutex> lk(r->m);
      if (sid != r->watched)
      {
        return;
      }
      if (r->closed)
      {
        r->dataAfterClose = true;
      }
      r->data.append(reinterpret_cast<const char *>(bv.data()), bv.size());
    };
    cbs.onClose = [r](SessionId sid, const TransportErrorInfo &err)
    {
      const unsigned long peek = ::ERR_peek_error();
      std::lock_guard<std::mutex> lk(r->m);
      if (sid != r->watched)
      {
        return;
      }
      r->closed = true;
      r->closeCode = err.code;
      r->closeErrno = err.sysErrno;
      r->errPeekInClose = peek;
    };
    tx->setCallbacks(cbs);
    REQUIRE(tx->start().isOk());
    port = testnet::getFreePortTCP();
    REQUIRE(tx->addListener("127.0.0.1", port, tls ? TlsMode::Server : TlsMode::None).isOk());
  }

  ~ResetServer() noexcept
  {
    try
    {
      tx->stop();
    }
    catch (...)
    {
    }
  }

  SessionId waitAccepted(std::size_t index)
  {
    SessionId sid = 0;
    REQUIRE(waitFor(
      [&]
      {
        std::lock_guard<std::mutex> lk(rec->m);
        if (rec->accepted.size() > index)
        {
          sid = rec->accepted[index];
          return true;
        }
        return false;
      },
      5000ms));
    return sid;
  }

  void watch(SessionId sid)
  {
    std::lock_guard<std::mutex> lk(rec->m);
    rec->watched = sid;
  }

  bool waitClosed()
  {
    return waitFor(
      [&]
      {
        std::lock_guard<std::mutex> lk(rec->m);
        return rec->closed;
      },
      5000ms);
  }
};

struct PeerFd
{
  int fd{-1};

  explicit PeerFd(int f) : fd(f) {}
  PeerFd(const PeerFd &) = delete;
  PeerFd &operator=(const PeerFd &) = delete;

  ~PeerFd()
  {
    if (fd >= 0)
    {
      ::close(fd);
    }
  }
};

struct TlsPeer
{
  std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)> ctx{nullptr, &::SSL_CTX_free};
  std::unique_ptr<SSL, decltype(&::SSL_free)> ssl{nullptr, &::SSL_free};

  void connect(int fd)
  {
    ctx.reset(::SSL_CTX_new(::TLS_client_method()));
    REQUIRE(ctx != nullptr);
    ssl.reset(::SSL_new(ctx.get()));
    REQUIRE(ssl != nullptr);
    ::SSL_set_fd(ssl.get(), fd);
    REQUIRE(::SSL_connect(ssl.get()) == 1);
  }
};

// Wait until every byte the peer wrote is acknowledged, so it sits in the engine
// socket's receive queue and SO_LINGER{1,0} discards nothing unsent.
void waitSendQueueEmpty(int fd)
{
  REQUIRE(waitFor(
    [&]
    {
      int outq = -1;
      return ::ioctl(fd, SIOCOUTQ, &outq) == 0 && outq == 0;
    },
    3000ms));
}

void resetPeer(PeerFd &peer)
{
  struct linger lg
  {
    1, 0
  };
  const int rc = ::setsockopt(peer.fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
  ::close(peer.fd);
  peer.fd = -1;
  REQUIRE(rc == 0);
}

void checkDrainedThenClosed(ResetServer &srv)
{
  REQUIRE(srv.waitClosed());

  std::size_t bytes = 0;
  bool dataAfterClose = false;
  TransportError closeCode = TransportError::Unknown;
  int closeErrno = 0;
  std::vector<std::uint32_t> passed;
  int changed = 0;
  {
    std::lock_guard<std::mutex> lk(srv.rec->m);
    bytes = srv.rec->data.size();
    dataAfterClose = srv.rec->dataAfterClose;
    closeCode = srv.rec->closeCode;
    closeErrno = srv.rec->closeErrno;
    std::lock_guard<std::mutex> fl(srv.filter->m);
    passed = srv.filter->passed;
    changed = srv.filter->changed.load();
  }

  const std::uint32_t first = passed.empty() ? 0u : passed[0];
  WARN("IP-T2 evidence: passedMasks=" << passed.size() << " firstMask=0x" << std::hex << first
                                      << std::dec << " hupOrErr="
                                      << ((first & (EPOLLHUP | EPOLLERR)) != 0)
                                      << " epollin=" << ((first & EPOLLIN) != 0)
                                      << " filterChanged=" << changed
                                      << " bytesBeforeClose=" << bytes << "/" << kPayload
                                      << " dataAfterClose=" << dataAfterClose);

  REQUIRE(bytes == kPayload);
  REQUIRE_FALSE(dataAfterClose);
  REQUIRE(closeCode == TransportError::PeerClosed);
  REQUIRE(closeErrno == ECONNRESET);
  REQUIRE(passed.size() == 1);
  REQUIRE((passed[0] & (EPOLLHUP | EPOLLERR)) != 0);
}
} // namespace

TEST_CASE("IP-T2 TCP: bytes received before a reset reach onData before onClose",
          "[reset_drain][ip_t2]")
{
  ResetServer srv(false, "", "");
  PeerFd peer(testnet::connectLoopbackTcp(srv.port));
  REQUIRE(peer.fd >= 0);
  const SessionId sid = srv.waitAccepted(0);
  srv.watch(sid);
  REQUIRE(runOnIo(*srv.tx, [&] { srv.filter->target.store(sid); }));

  const std::string payload(kPayload, 'r');
  REQUIRE(::send(peer.fd, payload.data(), payload.size(), MSG_NOSIGNAL) ==
          static_cast<ssize_t>(payload.size()));
  waitSendQueueEmpty(peer.fd);
  resetPeer(peer);

  checkDrainedThenClosed(srv);
}

TEST_CASE("IP-T2 TLS: bytes received before a reset reach onData before onClose",
          "[reset_drain][ip_t2]")
{
  std::string certFile, keyFile;
  REQUIRE(testCerts(certFile, keyFile));
  ResetServer srv(true, certFile, keyFile);

  PeerFd fd(testnet::connectLoopbackTcp(srv.port, 5));
  REQUIRE(fd.fd >= 0);
  TlsPeer peer;
  peer.connect(fd.fd);

  const SessionId sid = srv.waitAccepted(0);
  srv.watch(sid);
  // The engine's first application byte proves its side of the handshake is Open.
  REQUIRE(srv.tx->send(sid, "o", 1));
  char one = 0;
  REQUIRE(::SSL_read(peer.ssl.get(), &one, 1) == 1);

  REQUIRE(runOnIo(*srv.tx, [&] { srv.filter->target.store(sid); }));

  const std::string payload(kPayload, 't');
  REQUIRE(::SSL_write(peer.ssl.get(), payload.data(), static_cast<int>(payload.size())) ==
          static_cast<int>(payload.size()));
  waitSendQueueEmpty(fd.fd);
  resetPeer(fd);

  checkDrainedThenClosed(srv);
  {
    std::lock_guard<std::mutex> lk(srv.rec->m);
    REQUIRE(srv.rec->errPeekInClose == 0);
  }

  // Regression guard: a second TLS session on the same engine reads and writes.
  srv.filter->target.store(0);
  PeerFd fd2(testnet::connectLoopbackTcp(srv.port, 5));
  REQUIRE(fd2.fd >= 0);
  TlsPeer peer2;
  peer2.connect(fd2.fd);
  const SessionId sid2 = srv.waitAccepted(1);
  {
    std::lock_guard<std::mutex> lk(srv.rec->m);
    srv.rec->watched = sid2;
    srv.rec->data.clear();
    srv.rec->closed = false;
    srv.rec->dataAfterClose = false;
  }
  REQUIRE(srv.tx->send(sid2, "ok", 2));
  char two[2] = {0, 0};
  REQUIRE(::SSL_read(peer2.ssl.get(), two, 2) == 2);
  REQUIRE(std::string(two, 2) == "ok");

  REQUIRE(::SSL_write(peer2.ssl.get(), "in", 2) == 2);
  REQUIRE(waitFor(
    [&]
    {
      std::lock_guard<std::mutex> lk(srv.rec->m);
      return srv.rec->data.size() >= 2;
    },
    5000ms));
  std::lock_guard<std::mutex> lk(srv.rec->m);
  REQUIRE(srv.rec->data == "in");
}

TEST_CASE("IP-T3: a read-disabled session is not drained on a reset", "[reset_drain][ip_t3]")
{
  ResetServer srv(false, "", "");
  PeerFd peer(testnet::connectLoopbackTcp(srv.port));
  REQUIRE(peer.fd >= 0);
  const SessionId sid = srv.waitAccepted(0);
  srv.watch(sid);

  REQUIRE(srv.tx->setReadEnabled(sid, false));
  REQUIRE(runOnIo(*srv.tx, [] {}));

  const std::string payload(kPayload, 'd');
  REQUIRE(::send(peer.fd, payload.data(), payload.size(), MSG_NOSIGNAL) ==
          static_cast<ssize_t>(payload.size()));
  waitSendQueueEmpty(peer.fd);
  resetPeer(peer);

  REQUIRE(srv.waitClosed());
  std::lock_guard<std::mutex> lk(srv.rec->m);
  REQUIRE(srv.rec->data.empty());
  REQUIRE(srv.rec->closeCode == TransportError::PeerClosed);
  REQUIRE(srv.rec->closeErrno == ECONNRESET);
}
