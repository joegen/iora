// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_tcp_setup_close_codes.cpp
/// \brief TcpEngine deterministic setup-phase close codes and TLS setup budget
///        (tracker 2026-09-24-1, A9.3): Connect/ETIMEDOUT for a TCP-phase stall,
///        TLSHandshake/ETIMEDOUT for a handshake stall measured from
///        TCP-established, the handshake transport-abort discriminator in
///        sysErrno (A4.6), app close never relabelled, and a stale connect
///        timeout never closing a session past its TCP phase. Timer cases run
///        with high-resolution timers and with the GC fallback.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/network/http_client.hpp"
#include "iora/network/transport.hpp"
#include "tcp_connect_test_fixtures.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <sys/resource.h>

#include <cerrno>
#include <cstring>

using namespace tcptest;

namespace
{

struct TimerMode
{
  const char *name;
  bool highResolution;
  std::chrono::milliseconds slack;
};

const TimerMode kTimerModes[] = {
  {"high-resolution timers", true, 700ms},
  {"GC fallback (enableHighResolutionTimers=false)", false, 2500ms},
};

void applyTimerMode(TransportConfig &cfg, const TimerMode &mode)
{
  cfg.enableHighResolutionTimers = mode.highResolution;
  cfg.gcInterval = std::chrono::seconds(1);
}

std::string certPath()
{
  return std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_cert.pem";
}

enum class HelloAction
{
  RST,
  FIN,
  ALERT,
  CLOSE_NOTIFY
};

/// Raw TCP peer that accepts one connection, reads the complete ClientHello
/// record, then resets it, half-closes it cleanly, answers with a fatal alert, or
/// sends a close_notify alert and half-closes.
struct RawHelloPeer
{
  RawListener lst;
  std::atomic<bool> gotHello{false};
  std::atomic<bool> stopFlag{false};
  std::thread th;

  explicit RawHelloPeer(HelloAction action)
  {
    th = std::thread([this, action] { run(action); });
  }

  ~RawHelloPeer()
  {
    stopFlag = true;
    if (th.joinable())
    {
      th.join();
    }
  }

  static bool readRecord(int c)
  {
    std::vector<std::uint8_t> buf;
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (buf.size() >= 5)
      {
        std::size_t len = (static_cast<std::size_t>(buf[3]) << 8) | buf[4];
        if (buf.size() >= 5 + len)
        {
          return buf[0] == 0x16;
        }
      }
      pollfd p{c, POLLIN, 0};
      if (::poll(&p, 1, 100) <= 0)
      {
        continue;
      }
      std::uint8_t tmp[4096];
      ssize_t n = ::recv(c, tmp, sizeof(tmp), 0);
      if (n <= 0)
      {
        return false;
      }
      buf.insert(buf.end(), tmp, tmp + n);
    }
    return false;
  }

  void run(HelloAction action)
  {
    int c = acceptWithin(lst.fd, 5000ms);
    if (c < 0)
    {
      return;
    }
    if (!readRecord(c))
    {
      ::close(c);
      return;
    }
    gotHello = true;
    if (action == HelloAction::RST)
    {
      linger lg{1, 0};
      ::setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
      ::close(c);
      return;
    }
    if (action == HelloAction::FIN)
    {
      ::close(c);
      return;
    }
    if (action == HelloAction::CLOSE_NOTIFY)
    {
      const std::uint8_t closeNotify[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00};
      (void)::send(c, closeNotify, sizeof(closeNotify), MSG_NOSIGNAL);
      ::shutdown(c, SHUT_WR);
    }
    else
    {
      const std::uint8_t alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
      (void)::send(c, alert, sizeof(alert), MSG_NOSIGNAL);
    }
    while (!stopFlag.load())
    {
      pollfd q{c, POLLIN, 0};
      if (::poll(&q, 1, 50) > 0)
      {
        std::uint8_t tmp[512];
        if (::recv(c, tmp, sizeof(tmp), 0) <= 0)
        {
          break;
        }
      }
    }
    ::close(c);
  }
};

/// Raw OpenSSL TLS 1.3 server that REQUIRES a client certificate
/// (SSL_VERIFY_FAIL_IF_NO_PEER_CERT): with TLS 1.3 the client's handshake completes
/// before the server rejects the missing certificate with an alert.
struct ClientCertRequiredServer
{
  RawListener lst;
  SSL_CTX *ctx{nullptr};
  std::atomic<bool> acceptFailed{false};
  std::atomic<bool> stopFlag{false};
  std::thread th;

  ClientCertRequiredServer(const std::string &cert, const std::string &key)
  {
    ctx = ::SSL_CTX_new(TLS_server_method());
    REQUIRE(ctx != nullptr);
    REQUIRE(::SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1);
    REQUIRE(::SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) == 1);
    REQUIRE(::SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) == 1);
    REQUIRE(::SSL_CTX_load_verify_locations(ctx, cert.c_str(), nullptr) == 1);
    ::SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    th = std::thread([this] { run(); });
  }

  ~ClientCertRequiredServer()
  {
    stopFlag = true;
    if (th.joinable())
    {
      th.join();
    }
    ::SSL_CTX_free(ctx);
  }

  void run()
  {
    int c = acceptWithin(lst.fd, 5000ms);
    if (c < 0)
    {
      return;
    }
    SSL *ssl = ::SSL_new(ctx);
    ::SSL_set_fd(ssl, c);
    if (::SSL_accept(ssl) != 1)
    {
      acceptFailed = true;
    }
    while (!stopFlag.load())
    {
      pollfd q{c, POLLIN, 0};
      if (::poll(&q, 1, 50) > 0)
      {
        std::uint8_t tmp[512];
        if (::recv(c, tmp, sizeof(tmp), 0) <= 0)
        {
          break;
        }
      }
    }
    ::SSL_free(ssl);
    ::close(c);
  }
};

/// TcpEngine whose fetchPeerCertificate seam injects a verify result and/or an
/// ambient errno at the handshake completion gate.
class VerifySeamEngine : public TcpEngine
{
public:
  VerifySeamEngine(const TransportConfig &cfg, long verifyResult, bool dropPeerCert,
                   int ambientErrno)
      : TcpEngine(cfg), _verifyResult(verifyResult), _dropPeerCert(dropPeerCert),
        _ambientErrno(ambientErrno)
  {
  }

protected:
  X509 *fetchPeerCertificate(SSL *ssl) override
  {
    X509 *pc = TcpEngine::fetchPeerCertificate(ssl);
    if (_verifyResult != X509_V_OK)
    {
      ::SSL_set_verify_result(ssl, _verifyResult);
    }
    if (_dropPeerCert && pc != nullptr)
    {
      ::X509_free(pc);
      pc = nullptr;
    }
    errno = _ambientErrno;
    return pc;
  }

private:
  long _verifyResult;
  bool _dropPeerCert;
  int _ambientErrno;
};

void verifyingTlsClient(TransportConfig &c)
{
  c.clientTls.verifyPeer = true;
  c.clientTls.caFile = certPath();
}

/// Open a raw loopback TCP connection to \p port (blocking); -1 on failure.
int rawConnect(std::uint16_t port)
{
  int c = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (c < 0)
  {
    return -1;
  }
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons(port);
  if (::connect(c, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0)
  {
    ::close(c);
    return -1;
  }
  return c;
}

/// Restores RLIMIT_NOFILE on scope exit.
struct NoFileLimitGuard
{
  rlimit saved{};
  bool active{false};

  /// Lower the soft limit to the lowest free descriptor number, so the process's
  /// next descriptor allocation fails with EMFILE.
  bool exhaust()
  {
    if (::getrlimit(RLIMIT_NOFILE, &saved) != 0)
    {
      return false;
    }
    const int lowestFree = ::dup(STDERR_FILENO);
    if (lowestFree < 0)
    {
      return false;
    }
    ::close(lowestFree);
    rlimit lim = saved;
    lim.rlim_cur = static_cast<rlim_t>(lowestFree);
    active = ::setrlimit(RLIMIT_NOFILE, &lim) == 0;
    return active;
  }

  void restore()
  {
    if (active)
    {
      ::setrlimit(RLIMIT_NOFILE, &saved);
      active = false;
    }
  }

  ~NoFileLimitGuard() { restore(); }
};

} // namespace

TEST_CASE("TCP-phase stall (plain TCP and TLS): exactly one onClose(Connect, ETIMEDOUT), no bytes sent",
          "[tcp][tls][setup][close-codes]")
{
  for (const auto &mode : kTimerModes)
  {
    for (bool tls : {false, true})
    {
      SECTION(std::string(mode.name) + (tls ? " / TLS" : " / TCP"))
      {
        Blackhole bh;
        if (!fillOrSkip(bh))
        {
          return;
        }
        Client client(tls, [&](TransportConfig &c) {
          applyTimerMode(c, mode);
          c.connectTimeout = 300ms;
          c.handshakeTimeout = 200ms;
        });
        REQUIRE(client.tx->start().isOk());

        const auto start = std::chrono::steady_clock::now();
        auto cr = client.tx->connect("127.0.0.1", bh.lst.port, tls ? TlsMode::Client : TlsMode::None);
        REQUIRE(cr.isOk());
        REQUIRE(client.tx->send(cr.value(), "INVITE|", 7));
        REQUIRE(client.tx->send(cr.value(), "ACK|", 4));
        REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
        REQUIRE(client.stopAndCountCloses(cr.value()) == 1);

        const auto info = client.closeInfo(cr.value());
        const auto elapsed = client.closeTime(cr.value()) - start;
        REQUIRE(info.code == TransportError::Connect);
        REQUIRE(info.sysErrno == ETIMEDOUT);
        REQUIRE(info.message == "Connect timeout");
        REQUIRE(elapsed >= 300ms);
        REQUIRE(elapsed <= 300ms + mode.slack);
        REQUIRE(client.connectCount == 0);
        REQUIRE(client.tx->getStats().bytesOut == 0);
        REQUIRE(TA::connectingCount(*client.tx) == 0);
      }
    }
  }
}

TEST_CASE("TLS listener never answering ClientHello: TLSHandshake/ETIMEDOUT, budget from TCP-established",
          "[tcp][tls][setup][close-codes][budget]")
{
  for (const auto &mode : kTimerModes)
  {
    SECTION(mode.name)
    {
      std::mutex estMx;
      std::chrono::steady_clock::time_point establishedAt{};
      RawListener lst;
      Client client(true, [&](TransportConfig &c) {
        applyTimerMode(c, mode);
        c.connectTimeout = 400ms;
        c.handshakeTimeout = 500ms;
      });
      TA::setBeforeTcpEstablishedHook(*client.tx, [&](SessionId) {
        std::this_thread::sleep_for(250ms);
        std::lock_guard<std::mutex> lk(estMx);
        establishedAt = std::chrono::steady_clock::now();
      });
      REQUIRE(client.tx->start().isOk());

      const auto start = std::chrono::steady_clock::now();
      auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::Client);
      REQUIRE(cr.isOk());
      REQUIRE(client.tx->send(cr.value(), "OPTIONS|", 8));
      REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 6000ms));
      REQUIRE(client.stopAndCountCloses(cr.value()) == 1);

      const auto info = client.closeInfo(cr.value());
      const auto closedAt = client.closeTime(cr.value());
      std::chrono::steady_clock::time_point est;
      {
        std::lock_guard<std::mutex> lk(estMx);
        est = establishedAt;
      }
      REQUIRE(est != std::chrono::steady_clock::time_point{});
      REQUIRE(info.code == TransportError::TLSHandshake);
      REQUIRE(info.sysErrno == ETIMEDOUT);
      REQUIRE(info.message == "TLS handshake timeout");
      REQUIRE(closedAt - est >= 500ms);
      REQUIRE(closedAt - start >= 750ms);
      REQUIRE(closedAt - est <= 500ms + mode.slack);
      REQUIRE(client.connectCount == 0);
      REQUIRE(client.tx->getStats().bytesOut == 0);
    }
  }
}

TEST_CASE("a TLS handshake with queued sends never busy-loops on EPOLLOUT (client and server role)",
          "[tcp][tls][setup][epollout]")
{
  // Wakeup budget for a 500 ms window in which nothing arrives on the socket.
  constexpr std::uint64_t kMaxIdleWakeups = 20;

  SECTION("client: listener never answering ClientHello")
  {
    std::atomic<bool> established{false};
    RawListener lst;
    Client client(true, [](TransportConfig &c) {
      c.connectTimeout = 5000ms;
      c.handshakeTimeout = 5000ms;
    });
    TA::setBeforeTcpEstablishedHook(*client.tx, [&](SessionId) { established = true; });
    REQUIRE(client.tx->start().isOk());
    auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::Client);
    REQUIRE(cr.isOk());
    for (int i = 0; i < 3; ++i)
    {
      REQUIRE(client.tx->send(cr.value(), "OPTIONS|", 8));
    }
    REQUIRE(waitFor([&] { return established.load(); }));
    REQUIRE(runOnIo(*client.tx, [] {}));
    const auto before = client.tx->getStats().epollWakeups;
    std::this_thread::sleep_for(500ms);
    const auto wakeups = client.tx->getStats().epollWakeups - before;
    CAPTURE(wakeups);
    REQUIRE(wakeups < kMaxIdleWakeups);
    REQUIRE(client.closesFor(cr.value()) == 0);
    REQUIRE(client.tx->getStats().bytesOut == 0);
  }

  SECTION("server: accepted TLS session queues sends before the ClientHello arrives")
  {
    std::string cert, key;
    if (!certsOrSkip(cert, key))
    {
      return;
    }
    std::atomic<SessionId> acceptedSid{0};
    TransportConfig scfg{};
    scfg.serverTls.enabled = true;
    scfg.serverTls.defaultMode = TlsMode::Server;
    scfg.serverTls.certFile = cert;
    scfg.serverTls.keyFile = key;
    scfg.handshakeTimeout = 5000ms;
    TcpEngine srv{scfg};
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onAccept = [&](SessionId sid, const TransportAddress &) { acceptedSid = sid; };
    srv.setCallbacks(cbs);
    REQUIRE(srv.start().isOk());
    const std::uint16_t port = testnet::getFreePortTCP();
    REQUIRE(srv.addListener("127.0.0.1", port, TlsMode::Server).isOk());

    int raw = rawConnect(port);
    REQUIRE(raw >= 0);
    REQUIRE(waitFor([&] { return acceptedSid.load() != 0; }));
    for (int i = 0; i < 3; ++i)
    {
      REQUIRE(srv.send(acceptedSid.load(), "NOTIFY|", 7));
    }
    REQUIRE(runOnIo(srv, [] {}));
    const auto before = srv.getStats().epollWakeups;
    std::this_thread::sleep_for(500ms);
    const auto wakeups = srv.getStats().epollWakeups - before;
    ::close(raw);
    srv.stop();
    CAPTURE(wakeups);
    REQUIRE(wakeups < kMaxIdleWakeups);
    REQUIRE(srv.getStats().bytesOut == 0);
  }
}

TEST_CASE("TLS RST during ClientHello: TLSHandshake with sysErrno ECONNRESET", "[tcp][tls][setup][abort]")
{
  for (bool queuedSends : {false, true})
  {
    SECTION(queuedSends ? "with queued sends" : "without queued sends")
    {
      RawHelloPeer peer(HelloAction::RST);
      Client client(true, [](TransportConfig &c) { c.handshakeTimeout = 3000ms; });
      REQUIRE(client.tx->start().isOk());
      auto cr = client.tx->connect("127.0.0.1", peer.lst.port, TlsMode::Client);
      REQUIRE(cr.isOk());
      if (queuedSends)
      {
        REQUIRE(client.tx->send(cr.value(), "INVITE|", 7));
      }
      REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
      REQUIRE(peer.gotHello);
      REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
      const auto info = client.closeInfo(cr.value());
      REQUIRE(info.code == TransportError::TLSHandshake);
      REQUIRE(info.sysErrno != ETIMEDOUT);
      REQUIRE(info.sysErrno == ECONNRESET);
      REQUIRE(info.message == iora::core::errnoMessage(ECONNRESET));
      REQUIRE(client.tx->getStats().bytesOut == 0);
    }
  }
}

TEST_CASE("TLS FIN during ClientHello: TLSHandshake with sysErrno ECONNABORTED", "[tcp][tls][setup][abort]")
{
  RawHelloPeer peer(HelloAction::FIN);
  Client client(true, [](TransportConfig &c) { c.handshakeTimeout = 3000ms; });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", peer.lst.port, TlsMode::Client);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
  REQUIRE(peer.gotHello);
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
  const auto info = client.closeInfo(cr.value());
  REQUIRE(info.code == TransportError::TLSHandshake);
  REQUIRE(info.sysErrno == ECONNABORTED);
  REQUIRE_FALSE(info.message.empty());
  REQUIRE(info.message.find("lib(0)") == std::string::npos);
}

TEST_CASE("TLS alert or close_notify received during the handshake: TLSHandshake with sysErrno 0",
          "[tcp][tls][setup][abort]")
{
  for (HelloAction action : {HelloAction::ALERT, HelloAction::CLOSE_NOTIFY})
  {
    SECTION(action == HelloAction::ALERT ? "fatal alert" : "close_notify then FIN")
    {
      RawHelloPeer peer(action);
      Client client(true, [](TransportConfig &c) { c.handshakeTimeout = 3000ms; });
      REQUIRE(client.tx->start().isOk());
      auto cr = client.tx->connect("127.0.0.1", peer.lst.port, TlsMode::Client);
      REQUIRE(cr.isOk());
      REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
      REQUIRE(peer.gotHello);
      REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
      const auto info = client.closeInfo(cr.value());
      CAPTURE(info.message);
      REQUIRE(info.code == TransportError::TLSHandshake);
      REQUIRE(info.sysErrno == 0);
      REQUIRE(client.connectCount == 0);
    }
  }
}

TEST_CASE("in-handshake certificate verification failure: TLSHandshake with sysErrno 0",
          "[tcp][tls][setup][abort][verify]")
{
  std::string cert, key;
  if (!certsOrSkip(cert, key))
  {
    return;
  }
  SECTION("identity mismatch (verifyName wrong.example)")
  {
    SinkServer server(true, cert, key);
    Client client(true, verifyingTlsClient);
    REQUIRE(client.tx->start().isOk());
    iora::network::TlsClientOptions opts;
    opts.verifyName = "wrong.example";
    auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::Client, opts);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
    REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
    const auto info = client.closeInfo(cr.value());
    CAPTURE(info.message);
    REQUIRE(info.code == TransportError::TLSHandshake);
    REQUIRE(info.sysErrno == 0);
    REQUIRE(client.connectCount == 0);
  }
  SECTION("untrusted CA (system trust store only)")
  {
    SinkServer server(true, cert, key);
    Client client(true, [](TransportConfig &c) { c.clientTls.verifyPeer = true; });
    REQUIRE(client.tx->start().isOk());
    auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
    REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
    const auto info = client.closeInfo(cr.value());
    CAPTURE(info.message);
    REQUIRE(info.code == TransportError::TLSHandshake);
    REQUIRE(info.sysErrno == 0);
    REQUIRE(client.connectCount == 0);
  }
}

TEST_CASE("TLS 1.3 server requiring a client certificate the client lacks: onConnect, then TLSIO",
          "[tcp][tls][setup][mtls]")
{
  std::string cert, key;
  if (!certsOrSkip(cert, key))
  {
    return;
  }
  ClientCertRequiredServer server(cert, key);
  Client client(true, [](TransportConfig &c) { c.handshakeTimeout = 3000ms; });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", server.lst.port, TlsMode::Client);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
  const auto info = client.closeInfo(cr.value());
  CAPTURE(info.message);
  REQUIRE(server.acceptFailed);
  REQUIRE(client.connectCount == 1);
  REQUIRE(info.code != TransportError::TLSHandshake);
  REQUIRE(info.code != TransportError::Connect);
  REQUIRE(info.code == TransportError::TLSIO);
}

TEST_CASE("server role: an inbound TLS client that FINs before its ClientHello closes TLSHandshake, sysErrno 0",
          "[tcp][tls][setup][server-role]")
{
  std::string cert, key;
  if (!certsOrSkip(cert, key))
  {
    return;
  }
  SinkServer server(true, cert, key);
  int raw = rawConnect(server.port);
  REQUIRE(raw >= 0);
  REQUIRE(waitFor([&] { return server.accepted.load() == 1; }));
  ::close(raw);
  REQUIRE(waitFor([&] { return server.closes.load() >= 1; }));
  server.tx->stop();
  const auto infos = server.closeInfoList();
  REQUIRE(infos.size() == 1);
  CAPTURE(infos.front().message);
  REQUIRE(infos.front().code == TransportError::TLSHandshake);
  REQUIRE(infos.front().sysErrno == 0);
}

TEST_CASE("server role: an inbound TLS client that RSTs mid-handshake closes TLSHandshake, sysErrno 0",
          "[tcp][tls][setup][server-role]")
{
  std::string cert, key;
  if (!certsOrSkip(cert, key))
  {
    return;
  }
  SinkServer server(true, cert, key);
  int raw = rawConnect(server.port);
  REQUIRE(raw >= 0);
  REQUIRE(waitFor([&] { return server.accepted.load() == 1; }));
  // A partial TLS handshake record header claiming more bytes than follow, so the
  // server's SSL_do_handshake blocks reading; then RST. The server observes
  // ECONNRESET (SSL_ERROR_SYSCALL) -- which for a CLIENT role would be the
  // transport-abort discriminator. For this SERVER role, closeNow zeroes it (the
  // producer invariant: an inbound handshake abort has no reachability consumer).
  const std::uint8_t partialHello[] = {0x16, 0x03, 0x01, 0x01, 0x00};
  (void)::send(raw, partialHello, sizeof(partialHello), MSG_NOSIGNAL);
  linger lg{1, 0};
  ::setsockopt(raw, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
  ::close(raw);
  REQUIRE(waitFor([&] { return server.closes.load() >= 1; }));
  server.tx->stop();
  const auto infos = server.closeInfoList();
  REQUIRE(infos.size() == 1);
  CAPTURE(infos.front().message);
  CAPTURE(infos.front().sysErrno);
  REQUIRE(infos.front().code == TransportError::TLSHandshake);
  REQUIRE(infos.front().sysErrno == 0);
}

TEST_CASE("server role: an inbound TLS client that never sends ClientHello times out "
          "TLSHandshake, sysErrno 0",
          "[tcp][tls][setup][server-role]")
{
  std::string cert, key;
  if (!certsOrSkip(cert, key))
  {
    return;
  }
  SinkServer server(true, cert, key, [](TransportConfig &c) { c.handshakeTimeout = 500ms; });
  int raw = rawConnect(server.port);
  REQUIRE(raw >= 0);
  REQUIRE(waitFor([&] { return server.accepted.load() == 1; }));
  // Never send ClientHello: the server's handshake timeout fires. A CLIENT-role
  // timeout carries ETIMEDOUT (the discriminator); the SERVER role reports 0.
  REQUIRE(waitFor([&] { return server.closes.load() >= 1; }, 5000ms));
  server.tx->stop();
  const auto infos = server.closeInfoList();
  REQUIRE(infos.size() == 1);
  CAPTURE(infos.front().message);
  REQUIRE(infos.front().code == TransportError::TLSHandshake);
  REQUIRE(infos.front().sysErrno == 0);
  ::close(raw);
}

TEST_CASE("server role: an inbound TLS handshake with idleTimeout < handshakeTimeout is closed "
          "by the handshake budget (TLSHandshake), not idle-GC (GCClosed)",
          "[tcp][tls][setup][server-role][gc]")
{
  std::string cert, key;
  if (!certsOrSkip(cert, key))
  {
    return;
  }
  // GC path owns every deadline; idle (1s) would fire before the handshake budget
  // (4s) if an inbound handshaking session were not exempted from idle-GC (A4.4).
  SinkServer server(true, cert, key,
                    [](TransportConfig &c)
                    {
                      c.enableHighResolutionTimers = false;
                      c.gcInterval = std::chrono::seconds(1);
                      c.idleTimeout = std::chrono::seconds(1);
                      c.handshakeTimeout = 4000ms;
                    });
  int raw = rawConnect(server.port);
  REQUIRE(raw >= 0);
  REQUIRE(waitFor([&] { return server.accepted.load() == 1; }));
  REQUIRE(waitFor([&] { return server.closes.load() >= 1; }, 10000ms));
  server.tx->stop();
  const auto infos = server.closeInfoList();
  REQUIRE(infos.size() == 1);
  CAPTURE(infos.front().message);
  // The handshake budget owns it: TLSHandshake, never GCClosed "GC safety-net timeout".
  REQUIRE(infos.front().code == TransportError::TLSHandshake);
  REQUIRE(infos.front().sysErrno == 0);
  ::close(raw);
}

TEST_CASE("verify failure with a verify result colliding with SSL_ERROR codes: sysErrno 0",
          "[tcp][tls][setup][abort][verify]")
{
  for (long vr : {5L, 6L})
  {
    SECTION("verify result " + std::to_string(vr))
    {
      std::string cert;
      std::string key;
      if (!certsOrSkip(cert, key))
      {
        return;
      }
      SinkServer server(true, cert, key);
      Client client(true, verifyingTlsClient, [vr](const TransportConfig &c) {
        return std::make_unique<VerifySeamEngine>(c, vr, false, ECONNRESET);
      });
      REQUIRE(client.tx->start().isOk());
      auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
      REQUIRE(cr.isOk());
      REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
      REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
      const auto info = client.closeInfo(cr.value());
      REQUIRE(info.code == TransportError::TLSHandshake);
      REQUIRE(info.tlsError == vr);
      REQUIRE(info.sysErrno == 0);
      REQUIRE(client.connectCount == 0);
    }
  }
}

TEST_CASE("'no peer certificate' with ambient errno ETIMEDOUT never carries ETIMEDOUT",
          "[tcp][tls][setup][abort][verify]")
{
  std::string cert;
  std::string key;
  if (!certsOrSkip(cert, key))
  {
    return;
  }
  SinkServer server(true, cert, key);
  Client client(true, verifyingTlsClient, [](const TransportConfig &c) {
    return std::make_unique<VerifySeamEngine>(c, X509_V_OK, true, ETIMEDOUT);
  });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
  const auto info = client.closeInfo(cr.value());
  REQUIRE(info.code == TransportError::TLSHandshake);
  REQUIRE(info.message == "no peer certificate");
  REQUIRE(info.sysErrno != ETIMEDOUT);
  REQUIRE(info.sysErrno == 0);
}

TEST_CASE("handshakeFailureErrno / sslFailureMessage / drainSslErrors classify their inputs",
          "[tcp][tls][unit]")
{
  const unsigned long verifyFailed =
    ERR_PACK(ERR_LIB_SSL, 0, SSL_R_CERTIFICATE_VERIFY_FAILED);

  // handshakeFailureErrno is the role-AGNOSTIC raw classifier; the client/server
  // role scope is applied in closeNow (server-role TLSHandshake sysErrno is zeroed
  // centrally) and is pinned by the server-role integration cases below.
  // (1) SSL_ERROR_SYSCALL with an errno: that errno.
  REQUIRE(TA::handshakeFailureErrno(SSL_ERROR_SYSCALL, ECONNRESET, 0, false) == ECONNRESET);
  // (2) SSL_ERROR_SYSCALL, no errno, empty error queue: EOF without an alert.
  REQUIRE(TA::handshakeFailureErrno(SSL_ERROR_SYSCALL, 0, 0, false) == ECONNABORTED);
  // (3) SSL_ERROR_SYSCALL, no errno, a queued protocol error: TLS-protocol failure.
  REQUIRE(TA::handshakeFailureErrno(SSL_ERROR_SYSCALL, 0, verifyFailed, false) == 0);
  // (4) SSL_ERROR_SSL with a queued unexpected-EOF reason: transport abort.
  REQUIRE(TA::handshakeFailureErrno(SSL_ERROR_SSL, 0, verifyFailed, true) == ECONNABORTED);
  // (5) SSL_ERROR_SSL (alert / verify failure): 0.
  REQUIRE(TA::handshakeFailureErrno(SSL_ERROR_SSL, 0, verifyFailed, false) == 0);

  REQUIRE(TA::sslFailureMessage(SSL_ERROR_SYSCALL, 0, ECONNRESET) ==
          iora::core::errnoMessage(ECONNRESET));
  REQUIRE(TA::sslFailureMessage(SSL_ERROR_SYSCALL, 0, 0) == "unexpected EOF");
  const std::string sslMsg = TA::sslFailureMessage(SSL_ERROR_SSL, verifyFailed, 0);
  REQUIRE_FALSE(sslMsg.empty());
  REQUIRE(sslMsg.find("lib(0)") == std::string::npos);

  ::ERR_clear_error();
  ERR_raise(ERR_LIB_SSL, SSL_R_CERTIFICATE_VERIFY_FAILED);
  ERR_raise(ERR_LIB_SSL, SSL_R_UNEXPECTED_EOF_WHILE_READING);
  bool unexpectedEof = false;
  const unsigned long first = TA::drainSslErrors(unexpectedEof);
  REQUIRE(ERR_GET_REASON(first) == SSL_R_CERTIFICATE_VERIFY_FAILED);
  REQUIRE(unexpectedEof);
  REQUIRE(::ERR_peek_error() == 0);
  REQUIRE(TA::drainSslErrors(unexpectedEof) == 0);
  REQUIRE_FALSE(unexpectedEof);
}

TEST_CASE("local resource exhaustion at socket(): ResourceLimit with the errno, never Connect",
          "[tcp][setup][resource]")
{
  REQUIRE(TA::isLocalResourceErrno(EMFILE));
  REQUIRE(TA::isLocalResourceErrno(ENFILE));
  REQUIRE(TA::isLocalResourceErrno(ENOBUFS));
  REQUIRE(TA::isLocalResourceErrno(ENOMEM));
  REQUIRE(TA::isLocalResourceErrno(EADDRNOTAVAIL));
  REQUIRE_FALSE(TA::isLocalResourceErrno(ECONNREFUSED));
  REQUIRE_FALSE(TA::isLocalResourceErrno(ETIMEDOUT));
  REQUIRE_FALSE(TA::isLocalResourceErrno(ENETUNREACH));

  RawListener lst;
  Client client;
  REQUIRE(client.tx->start().isOk());

  bool closed = false;
  {
    NoFileLimitGuard limit;
    REQUIRE(limit.exhaust());
    auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::None);
    closed = cr.isOk() && waitFor([&] { return client.closesFor(cr.value()) >= 1; });
    limit.restore();
    REQUIRE(cr.isOk());
    REQUIRE(closed);
    REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
    const auto info = client.closeInfo(cr.value());
    CAPTURE(info.message);
    REQUIRE(info.code == TransportError::ResourceLimit);
    REQUIRE(info.sysErrno == EMFILE);
    REQUIRE(client.connectCount == 0);
    REQUIRE(TA::connectingCount(*client.tx) == 0);
  }
}

TEST_CASE("a GC safety-net close (maxConnAge) during setup is not relabelled", "[tcp][setup][close-codes][relabel]")
{
  for (bool tls : {false, true})
  {
    SECTION(tls ? "TLS handshake phase" : "TCP phase")
    {
      Blackhole bh;
      RawListener silent;
      if (!tls && !fillOrSkip(bh))
      {
        return;
      }
      Client client(tls, [](TransportConfig &c) {
        c.gcInterval = std::chrono::seconds(1);
        c.maxConnAge = std::chrono::seconds(1);
        c.connectTimeout = 10000ms;
        c.handshakeTimeout = 10000ms;
      });
      REQUIRE(client.tx->start().isOk());
      auto cr = client.tx->connect("127.0.0.1", tls ? silent.port : bh.lst.port,
                                   tls ? TlsMode::Client : TlsMode::None);
      REQUIRE(cr.isOk());
      REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 5000ms));
      REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
      const auto info = client.closeInfo(cr.value());
      REQUIRE(info.message == "GC safety-net timeout");
      REQUIRE(info.code == TransportError::GCClosed);
    }
  }
}

TEST_CASE("a slow connect with queued sends never closes as a write stall", "[tcp][setup][close-codes][stall]")
{
  for (const auto &mode : kTimerModes)
  {
    SECTION(mode.name)
    {
      Blackhole bh;
      if (!fillOrSkip(bh))
      {
        return;
      }
      Client client(false, [&](TransportConfig &c) {
        applyTimerMode(c, mode);
        c.connectTimeout = mode.highResolution ? 600ms : 1500ms;
        c.writeStallTimeout = 100ms;
      });
      REQUIRE(client.tx->start().isOk());
      auto cr = client.tx->connect("127.0.0.1", bh.lst.port, TlsMode::None);
      REQUIRE(cr.isOk());
      REQUIRE(client.tx->send(cr.value(), "stall|", 6));
      REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 6000ms));
      REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
      const auto info = client.closeInfo(cr.value());
      REQUIRE(info.code == TransportError::Connect);
      REQUIRE(info.sysErrno == ETIMEDOUT);
      REQUIRE(info.message == "Connect timeout");
    }
  }
}

TEST_CASE("app close() of a connecting sid is never relabelled Connect", "[tcp][setup][close-codes]")
{
  for (const auto &mode : kTimerModes)
  {
    SECTION(mode.name)
    {
      Blackhole bh;
      if (!fillOrSkip(bh))
      {
        return;
      }
      Client client(false, [&](TransportConfig &c) {
        applyTimerMode(c, mode);
        c.connectTimeout = 3000ms;
      });
      REQUIRE(client.tx->start().isOk());
      auto cr = client.tx->connect("127.0.0.1", bh.lst.port, TlsMode::None);
      REQUIRE(cr.isOk());
      REQUIRE(client.tx->send(cr.value(), "x", 1));
      bool present = false;
      REQUIRE(runOnIo(*client.tx, [&] { present = TA::hasSession(*client.tx, cr.value()); }));
      REQUIRE(present); // still in the TCP phase
      REQUIRE(client.closesFor(cr.value()) == 0);
      REQUIRE(client.tx->close(cr.value()));
      REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }));
      REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
      const auto info = client.closeInfo(cr.value());
      REQUIRE(info.code != TransportError::Connect);
      REQUIRE(info.code == TransportError::Unknown);
      REQUIRE(info.message == "closed by app");
      REQUIRE(info.sysErrno == 0);
    }
  }
}

TEST_CASE("TCP-established delayed past connectTimeout never closes Connect",
          "[tcp][setup][close-codes][stale]")
{
  for (const auto &mode : kTimerModes)
  {
    for (bool tls : {false, true})
    {
      SECTION(std::string(mode.name) + (tls ? " / TLS" : " / TCP"))
      {
        std::string cert;
        std::string key;
        if (tls && !certsOrSkip(cert, key))
        {
          return;
        }
        SinkServer server(tls, cert, key);
        Client client(tls, [&](TransportConfig &c) {
          applyTimerMode(c, mode);
          c.connectTimeout = 200ms;
          c.handshakeTimeout = 3000ms;
        });
        const auto hookSleep = mode.highResolution ? 500ms : 1500ms;
        TA::setBeforeTcpEstablishedHook(
          *client.tx, [hookSleep](SessionId) { std::this_thread::sleep_for(hookSleep); });
        REQUIRE(client.tx->start().isOk());
        auto cr = client.tx->connect("127.0.0.1", server.port, tls ? TlsMode::Client : TlsMode::None);
        REQUIRE(cr.isOk());
        REQUIRE(client.tx->send(cr.value(), "late|", 5));
        REQUIRE(waitFor([&] { return client.connectCount == 1 || client.closesFor(cr.value()) >= 1; },
                        6000ms));
        // Barrier: a connect-timeout close enqueued while the hook slept is FIFO
        // before this closure, so it has been processed (and filtered) by now.
        REQUIRE(runOnIo(*client.tx, [] {}));
        if (client.closesFor(cr.value()) >= 1)
        {
          REQUIRE(client.closeInfo(cr.value()).code == TransportError::TLSHandshake);
        }
        else
        {
          REQUIRE(client.connectCount == 1);
          REQUIRE(waitFor([&] { return server.data() == "late|"; }));
        }
        REQUIRE(client.closeInfo(cr.value()).code != TransportError::Connect);
      }
    }
  }
}

TEST_CASE("a slow but progressing drain never closes as a write stall", "[tcp][stall][progress]")
{
  RawListener lst;
  int rcv = 4096;
  REQUIRE(::setsockopt(lst.fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)) == 0);
  Client client(false, [](TransportConfig &c) {
    c.writeStallTimeout = 300ms;
    c.soSndBuf = 4096;
  });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return client.connectCount == 1; }));
  int peer = acceptWithin(lst.fd, 3000ms);
  REQUIRE(peer >= 0);

  const std::size_t chunk = 8192;
  const std::size_t chunks = 48;
  std::string expected;
  for (std::size_t i = 0; i < chunks; ++i)
  {
    const std::string part = patternPayload(i * chunk, chunk);
    expected += part;
    REQUIRE(client.tx->send(cr.value(), part.data(), part.size()));
  }

  std::string rx;
  const auto start = std::chrono::steady_clock::now();
  while (rx.size() < expected.size() && std::chrono::steady_clock::now() - start < 20s)
  {
    std::this_thread::sleep_for(10ms);
    pollfd p{peer, POLLIN, 0};
    if (::poll(&p, 1, 0) <= 0)
    {
      continue;
    }
    char buf[2048];
    ssize_t n = ::recv(peer, buf, sizeof(buf), MSG_DONTWAIT);
    if (n <= 0)
    {
      break;
    }
    rx.append(buf, static_cast<std::size_t>(n));
  }
  const auto drainTime = std::chrono::steady_clock::now() - start;
  // Stop while the peer is still open: the only close must be the shutdown one.
  REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
  ::close(peer);

  REQUIRE(drainTime > 600ms);
  REQUIRE(rx.size() == expected.size());
  REQUIRE(rx == expected);
  REQUIRE(client.closeInfo(cr.value()).message == "shutdown");
}

TEST_CASE("a partial first write arms the write-stall timer", "[tcp][stall][partial]")
{
  RawListener lst;
  int rcv = 4096;
  REQUIRE(::setsockopt(lst.fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)) == 0);
  Client client(false, [](TransportConfig &c) {
    c.writeStallTimeout = 200ms;
    c.gcInterval = std::chrono::seconds(60);
    c.soSndBuf = 4096;
  });
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  REQUIRE(waitFor([&] { return client.connectCount == 1; }));
  int peer = acceptWithin(lst.fd, 3000ms);
  REQUIRE(peer >= 0);

  const std::string big = patternPayload(0, 256 * 1024);
  const auto start = std::chrono::steady_clock::now();
  REQUIRE(client.tx->send(cr.value(), big.data(), big.size()));
  REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 3000ms));
  const auto elapsed = client.closeTime(cr.value()) - start;
  const auto info = client.closeInfo(cr.value());
  ::close(peer);

  REQUIRE(client.tx->getStats().bytesOut > 0);
  REQUIRE(client.tx->getStats().bytesOut < big.size());
  REQUIRE(info.code == TransportError::Timeout);
  REQUIRE(info.message == "Write stall timeout");
  REQUIRE(elapsed >= 200ms);
  REQUIRE(elapsed < 1500ms);
}

TEST_CASE("TimerService at capacity: runGc applies the deadline of a phase whose timer is not armed",
          "[tcp][timers][cap]")
{
  SECTION("connect (TCP phase)")
  {
    Blackhole bh;
    if (!fillOrSkip(bh))
    {
      return;
    }
    Client client(false, [](TransportConfig &c) {
      c.connectTimeout = 300ms;
      c.gcInterval = std::chrono::seconds(1);
    });
    TA::setMaxConcurrentTimers(*client.tx, 0);
    REQUIRE(client.tx->start().isOk());
    auto cr = client.tx->connect("127.0.0.1", bh.lst.port, TlsMode::None);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 4000ms));
    REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
    const auto info = client.closeInfo(cr.value());
    REQUIRE(info.code == TransportError::Connect);
    REQUIRE(info.sysErrno == ETIMEDOUT);
    REQUIRE(info.message == "Connect timeout");
  }
  SECTION("TLS handshake")
  {
    RawListener lst;
    Client client(true, [](TransportConfig &c) {
      c.connectTimeout = 5000ms;
      c.handshakeTimeout = 300ms;
      c.gcInterval = std::chrono::seconds(1);
    });
    TA::setMaxConcurrentTimers(*client.tx, 0);
    REQUIRE(client.tx->start().isOk());
    auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::Client);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 4000ms));
    REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
    const auto info = client.closeInfo(cr.value());
    REQUIRE(info.code == TransportError::TLSHandshake);
    REQUIRE(info.sysErrno == ETIMEDOUT);
    REQUIRE(info.message == "TLS handshake timeout");
  }
  SECTION("write stall")
  {
    RawListener lst;
    int rcv = 4096;
    REQUIRE(::setsockopt(lst.fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)) == 0);
    Client client(false, [](TransportConfig &c) {
      c.writeStallTimeout = 300ms;
      c.gcInterval = std::chrono::seconds(1);
      c.soSndBuf = 4096;
    });
    TA::setMaxConcurrentTimers(*client.tx, 0);
    REQUIRE(client.tx->start().isOk());
    auto cr = client.tx->connect("127.0.0.1", lst.port, TlsMode::None);
    REQUIRE(cr.isOk());
    REQUIRE(waitFor([&] { return client.connectCount == 1; }));
    int peer = acceptWithin(lst.fd, 3000ms);
    REQUIRE(peer >= 0);
    const std::string big = patternPayload(0, 256 * 1024);
    REQUIRE(client.tx->send(cr.value(), big.data(), big.size()));
    REQUIRE(waitFor([&] { return client.closesFor(cr.value()) >= 1; }, 4000ms));
    REQUIRE(client.stopAndCountCloses(cr.value()) == 1);
    ::close(peer);
    const auto info = client.closeInfo(cr.value());
    REQUIRE(info.code == TransportError::Timeout);
    REQUIRE(info.message == "Write stall timeout");
    REQUIRE(client.tx->getStats().bytesOut > 0);
  }
}

TEST_CASE("a timer close that can be neither enqueued nor retried falls back to the GC deadline",
          "[tcp][timers][cap]")
{
  Blackhole bh;
  if (!fillOrSkip(bh))
  {
    return;
  }
  Client client(false, [](TransportConfig &c) {
    c.connectTimeout = 300ms;
    c.gcInterval = std::chrono::seconds(1);
  });
  TA::setMaxConcurrentTimers(*client.tx, 4);
  REQUIRE(client.tx->start().isOk());
  auto cr = client.tx->connect("127.0.0.1", bh.lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  const SessionId sid = cr.value();
  REQUIRE(waitFor([&] { return TA::connectingCount(*client.tx) == 0; }));

  // The state after the connect timer fired: its id is still recorded, nothing is armed.
  bool cancelled = false;
  REQUIRE(runOnIo(*client.tx, [&] { cancelled = TA::cancelConnectTimerKeepId(*client.tx, sid); }));
  REQUIRE(cancelled);
  REQUIRE(TA::fillTimerCapacity(*client.tx) >= 1);
  TA::injectEnqueueFailure(*client.tx, true);
  TA::fireConnectTimeoutClose(*client.tx, sid); // enqueue fails; the retry cannot be scheduled
  TA::injectEnqueueFailure(*client.tx, false);

  REQUIRE(waitFor([&] { return client.closesFor(sid) >= 1; }, 4000ms));
  REQUIRE(client.stopAndCountCloses(sid) == 1);
  const auto info = client.closeInfo(sid);
  REQUIRE(info.code == TransportError::Connect);
  REQUIRE(info.sysErrno == ETIMEDOUT);
  REQUIRE(info.message == "Connect timeout");
}

TEST_CASE("plain TCP: an EPOLLIN without EPOLLOUT during the TCP phase probes establishment, never recv first",
          "[tcp][setup][epollin]")
{
  Blackhole bh;
  if (!fillOrSkip(bh))
  {
    return;
  }

  std::mutex m;
  std::vector<std::string> order;
  std::string data;
  std::vector<TransportErrorInfo> closeInfos;
  std::atomic<int> epollInOnlyDispatches{0};
  TransportConfig cfg{};
  cfg.connectTimeout = 5000ms;
  TcpEngine tx{cfg};
  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onConnect = [&](SessionId, const TransportAddress &)
  {
    std::lock_guard<std::mutex> lk(m);
    order.emplace_back("connect");
  };
  cbs.onData = [&](SessionId, iora::core::BufferView v, std::chrono::steady_clock::time_point)
  {
    std::lock_guard<std::mutex> lk(m);
    order.emplace_back("data");
    data.append(reinterpret_cast<const char *>(v.data()), v.size());
  };
  cbs.onClose = [&](SessionId, const TransportErrorInfo &e)
  {
    std::lock_guard<std::mutex> lk(m);
    closeInfos.push_back(e);
  };
  tx.setCallbacks(cbs);
  TA::setSessionEventFilterHook(tx, [&](SessionId, std::uint32_t ev) -> std::uint32_t {
    const std::uint32_t out = ev & ~static_cast<std::uint32_t>(EPOLLOUT);
    if ((out & EPOLLIN) != 0)
    {
      epollInOnlyDispatches++;
    }
    return (out & (EPOLLIN | EPOLLHUP | EPOLLERR | EPOLLRDHUP)) != 0 ? out : 0;
  });
  REQUIRE(tx.start().isOk());

  auto cr = tx.connect("127.0.0.1", bh.lst.port, TlsMode::None);
  REQUIRE(cr.isOk());
  bool present = false;
  REQUIRE(runOnIo(tx, [&] { present = TA::hasSession(tx, cr.value()); }));
  REQUIRE(present); // Cmd::Connect processed; the connect sits in the TCP phase
  {
    std::lock_guard<std::mutex> lk(m);
    REQUIRE(order.empty());
  }

  int filler = ::accept(bh.lst.fd, nullptr, nullptr);
  REQUIRE(filler >= 0);
  int peer = acceptWithin(bh.lst.fd, 4000ms);
  REQUIRE(peer >= 0);
  REQUIRE(::send(peer, "hello", 5, MSG_NOSIGNAL) == 5);

  const bool delivered = waitFor([&] {
    std::lock_guard<std::mutex> lk(m);
    return data == "hello";
  }, 3000ms);
  // Stop while the peer is still open: the only close must be the shutdown one.
  tx.stop();
  ::close(peer);
  ::close(filler);

  REQUIRE(delivered);
  REQUIRE(epollInOnlyDispatches >= 1);
  {
    std::lock_guard<std::mutex> lk(m);
    REQUIRE(closeInfos.size() == 1);
    REQUIRE(closeInfos.front().message == "shutdown");
    REQUIRE(order.size() >= 2);
    REQUIRE(order.front() == "connect");
  }
}

TEST_CASE("isConnectPhaseTimeout classifies every connect-timeout producer and nothing else",
          "[http][connect-timeout][a7]")
{
  using iora::network::isConnectPhaseTimeout;
  REQUIRE(isConnectPhaseTimeout(TransportErrorInfo{TransportError::Timeout, "connectSync timed out"}));
  REQUIRE(isConnectPhaseTimeout(TransportErrorInfo{TransportError::Connect, "Connect timeout", ETIMEDOUT, 0}));
  REQUIRE(isConnectPhaseTimeout(
    TransportErrorInfo{TransportError::TLSHandshake, "TLS handshake timeout", ETIMEDOUT, 0}));
  REQUIRE_FALSE(isConnectPhaseTimeout(
    TransportErrorInfo{TransportError::Connect, "Connection refused", ECONNREFUSED, 0}));
  REQUIRE_FALSE(isConnectPhaseTimeout(TransportErrorInfo{TransportError::Connect, "x", 0, 0}));
  REQUIRE_FALSE(isConnectPhaseTimeout(
    TransportErrorInfo{TransportError::TLSHandshake, "Connection reset by peer", ECONNRESET, 0}));
  REQUIRE_FALSE(isConnectPhaseTimeout(TransportErrorInfo{TransportError::TLSHandshake, "alert", 0, 6}));
  REQUIRE_FALSE(isConnectPhaseTimeout(TransportErrorInfo{TransportError::Resolve, "resolve timeout", 0, 0}));
  REQUIRE_FALSE(isConnectPhaseTimeout(TransportErrorInfo{TransportError::Socket, "x", ETIMEDOUT, 0}));
}

TEST_CASE("connectSync watchdog path: engine connectTimeout < connectSync timeout -> Connect/ETIMEDOUT, a connect timeout",
          "[http][connect-timeout][a7][watchdog]")
{
  Blackhole bh;
  if (!fillOrSkip(bh))
  {
    return;
  }
  TransportConfig cfg{};
  cfg.connectTimeout = 200ms;
  auto transport = iora::network::Transport::tcp(cfg);
  REQUIRE(transport->start().isOk());

  const auto start = std::chrono::steady_clock::now();
  auto r = transport->connectSync("127.0.0.1", bh.lst.port, TlsMode::None, 5000ms);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  REQUIRE(r.isErr());
  REQUIRE(r.error().code == TransportError::Connect);
  REQUIRE(r.error().sysErrno == ETIMEDOUT);
  REQUIRE(r.error().message == "Connect timeout");
  REQUIRE(elapsed >= 200ms);
  REQUIRE(elapsed < 2000ms);
  REQUIRE(iora::network::isConnectPhaseTimeout(r.error()));
  transport->stop();
}

TEST_CASE("connectSync TLS-stall watchdog path: TLSHandshake/ETIMEDOUT, a connect timeout",
          "[http][connect-timeout][a7][watchdog][tls]")
{
  RawListener lst;
  TransportConfig cfg{};
  cfg.connectTimeout = 1000ms;
  cfg.handshakeTimeout = 200ms;
  cfg.clientTls.enabled = true;
  cfg.clientTls.defaultMode = TlsMode::Client;
  cfg.clientTls.verifyPeer = false;
  auto transport = iora::network::Transport::tcp(cfg);
  REQUIRE(transport->start().isOk());

  const auto start = std::chrono::steady_clock::now();
  auto r = transport->connectSync("127.0.0.1", lst.port, TlsMode::Client, 5000ms);
  const auto elapsed = std::chrono::steady_clock::now() - start;
  REQUIRE(r.isErr());
  REQUIRE(r.error().code == TransportError::TLSHandshake);
  REQUIRE(r.error().sysErrno == ETIMEDOUT);
  REQUIRE(r.error().message == "TLS handshake timeout");
  REQUIRE(elapsed >= 200ms);
  REQUIRE(elapsed < 2000ms);
  REQUIRE(iora::network::isConnectPhaseTimeout(r.error()));
  transport->stop();
}

TEST_CASE("connectSyncCancellable keeps waiting through engine connect-phase timeouts until its deadline",
          "[transport][connect-timeout][cancellable]")
{
  SECTION("TCP phase: engine connectTimeout 50ms")
  {
    Blackhole bh;
    if (!fillOrSkip(bh))
    {
      return;
    }
    TransportConfig cfg{};
    cfg.connectTimeout = 50ms;
    auto transport = iora::network::Transport::tcp(cfg);
    REQUIRE(transport->start().isOk());
    iora::network::CancellationToken token;
    const auto start = std::chrono::steady_clock::now();
    auto r = transport->connectSyncCancellable("127.0.0.1", bh.lst.port, token, TlsMode::None, 400ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    transport->stop();
    REQUIRE(r.isErr());
    REQUIRE(r.error().code == TransportError::Timeout);
    REQUIRE(r.error().message == "connectSync timed out");
    REQUIRE(elapsed >= 380ms);
  }
  SECTION("TLS handshake: engine handshakeTimeout 50ms")
  {
    RawListener lst(64);
    TransportConfig cfg{};
    cfg.connectTimeout = 2000ms;
    cfg.handshakeTimeout = 50ms;
    cfg.clientTls.enabled = true;
    cfg.clientTls.defaultMode = TlsMode::Client;
    cfg.clientTls.verifyPeer = false;
    auto transport = iora::network::Transport::tcp(cfg);
    REQUIRE(transport->start().isOk());
    iora::network::CancellationToken token;
    const auto start = std::chrono::steady_clock::now();
    auto r = transport->connectSyncCancellable("127.0.0.1", lst.port, token, TlsMode::Client, 400ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    transport->stop();
    REQUIRE(r.isErr());
    REQUIRE(r.error().code == TransportError::Timeout);
    REQUIRE(r.error().message == "connectSync timed out");
    REQUIRE(elapsed >= 380ms);
  }
}

TEST_CASE("HttpClient https TLS stall (accept-then-silent listener) throws HttpConnectTimeoutError",
          "[http][connect-timeout][a7][tls]")
{
  RawListener lst;
  iora::network::HttpClient::Config cfg;
  cfg.connectTimeout = 150ms;
  cfg.requestTimeout = 1000ms;
  cfg.reuseConnections = false;
  iora::network::HttpClient client(cfg);
  iora::network::HttpClient::TlsConfig tls;
  tls.verifyPeer = false;
  client.setTlsConfig(tls);

  bool typed = false;
  bool notSent = false;
  std::string what;
  const auto start = std::chrono::steady_clock::now();
  try
  {
    (void)client.get("https://127.0.0.1:" + std::to_string(lst.port) + "/");
  }
  catch (const std::exception &e)
  {
    typed = dynamic_cast<const iora::network::HttpConnectTimeoutError *>(&e) != nullptr;
    notSent = dynamic_cast<const iora::network::HttpRequestNotSentError *>(&e) != nullptr;
    what = e.what();
  }
  const auto elapsed = std::chrono::steady_clock::now() - start;
  CAPTURE(what);
  REQUIRE(typed);
  REQUIRE(notSent);
  REQUIRE((what.find("timeout") != std::string::npos || what.find("timed out") != std::string::npos));
  REQUIRE(elapsed < 3000ms);
}
