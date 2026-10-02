// Non-maskable regression LOCK for the engine's per-I/O-thread SIGPIPE block
// (tcp_engine.hpp _loop lambda: pthread_sigmask(SIG_BLOCK, {SIGPIPE})), and for the
// TLS error-queue hygiene fixes (ERR_clear_error before each SSL op; full-drain in
// closeTlsIo; SSL_set_quiet_shutdown on a fatal error; close_notify still sent on a
// clean close).
//
// Tracker: coding_trackers tasks/iora/ongoing/2026-09-25-17_tls-write-closed-socket-sigpipe-crash_P0
//
// DEDICATED binary by design: SIGPIPE MUST be at SIG_DFL here (this file must NOT call
// testnet::ignoreSigpipeForTestProcess()), so that removing the engine's per-thread
// block makes a write-after-close abort the process (the mutation check). Every TLS peer
// is engine-backed (SinkServer / EchoServer -> their I/O threads are themselves
// SIGPIPE-guarded), so no bare-OpenSSL harness thread is exposed in this binary.
//
// MUTATION CHECKS (manual, recorded in the tracker):
//   - remove the pthread_sigmask(SIG_BLOCK,{SIGPIPE}) in tcp_engine.hpp's _loop lambda
//     -> this binary aborts with signal SIGPIPE (exit 141)  [locks Phase 3]
//   - remove the ERR_clear_error() before SSL_read in readAvail -> the DETERMINISTIC
//     stale-ERR injection test fails (the healthy session is spuriously closed). The
//     two-session test is a POSITIVE integration test, not a 3b mutation discriminator
//     (see its header); 3b.2/3b.3 are defense-in-depth over 3b.1.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "network/tcp_connect_test_fixtures.hpp"
#include "network/tcp_engine_test_access.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <sys/socket.h>
#include <vector>

using namespace iora::network;
using namespace tcptest;
using namespace std::chrono_literals;

namespace
{

// The lock's non-maskability precondition, asserted on the thread that starts the engine
// (the I/O thread inherits ITS mask). SIG_DFL disposition catches an inherited SIG_IGN;
// the unblocked-mask check catches an inherited pthread_sigmask block. Either would make
// a removed engine block go undetected (the mutation check would pass vacuously).
void requireSigpipeDefaultAndUnblocked()
{
  struct sigaction oldSa;
  REQUIRE(::sigaction(SIGPIPE, nullptr, &oldSa) == 0);
  REQUIRE(oldSa.sa_handler == SIG_DFL);
  sigset_t cur{};
  REQUIRE(::pthread_sigmask(SIG_BLOCK, nullptr, &cur) == 0);
  REQUIRE(sigismember(&cur, SIGPIPE) == 0);
}

// Shared test certs; REQUIRE (not skip) so a missing-cert environment FAILS this
// non-maskable lock rather than passing vacuously.
void requireCerts(std::string &certFile, std::string &keyFile)
{
  REQUIRE(testCerts(certFile, keyFile));
}

// Engine subclass with two one-shot, sid-targeted fault hooks, both consumed on the I/O
// thread:
//   - beforeSslWrite: ::shutdown(ownFd, SHUT_WR) the target session's OWN socket right
//     before SSL_write, so SSL_write hits EPIPE (write after local SHUT_WR) and would
//     raise SIGPIPE on the I/O thread absent the per-thread block.
//   - beforeSslRead: ERR_raise(ERR_LIB_SYS, EPIPE) a STALE error-queue entry before the
//     next SSL_read, so (pre-fix) SSL_get_error on the following WANT_READ is misclassified
//     and the session is spuriously closed; the ERR_clear_error added before SSL_read (after
//     this hook) wipes it, so post-fix the session survives.
// shutWrTarget is std::atomic<SessionId> (sentinel 0; ids start at 1 and never repeat),
// matched one-shot by sid. errInjectArmed is a one-shot bool armed BEFORE connect (the
// single-session injection test has only this engine's one session, so it fires
// deterministically on that session's first post-handshake read -- no post-connect arming
// race). Both are consumed with a single-attempt exchange/CAS.
class FaultEngine : public TcpEngine
{
public:
  using TcpEngine::TcpEngine;

  std::atomic<SessionId> shutWrTarget{0};
  std::atomic<bool> shutWrFired{false};
  std::atomic<bool> shutWrFdOk{true};

  std::atomic<bool> errInjectArmed{false};
  std::atomic<bool> errInjectFired{false};

protected:
  bool beforeSslWrite(SessionId sid, std::size_t) override
  {
    SessionId expected = sid;
    if (shutWrTarget.compare_exchange_strong(expected, 0))
    {
      const int fd = TcpEngineTestAccess::sessionFd(*this, sid);
      if (fd >= 0)
      {
        ::shutdown(fd, SHUT_WR);
        shutWrFired.store(true);
      }
      else
      {
        shutWrFdOk.store(false); // never ::shutdown(-1)
      }
    }
    return true;
  }

  bool beforeSslRead(SessionId) override
  {
    if (errInjectArmed.exchange(false))
    {
      ERR_raise(ERR_LIB_SYS, EPIPE); // ERR_raise is a macro; no :: qualifier
      errInjectFired.store(true);
    }
    return true;
  }
};

std::unique_ptr<TcpEngine> makeFaultEngine(const TransportConfig &cfg)
{
  return std::make_unique<FaultEngine>(cfg);
}

// Minimal TLS echo server (engine-backed, so its I/O thread blocks SIGPIPE). Echoes every
// received byte and records per-session close reasons. Used to drive a REAL inbound read
// on a session after an unrelated session on the same client I/O thread has failed.
struct EchoServer
{
  std::uint16_t port{0};
  std::mutex m;
  std::vector<TransportErrorInfo> closeInfos;
  std::unique_ptr<TcpEngine> tx; // declared LAST so it is destroyed FIRST (stop() joins the
                                 // I/O thread before m/closeInfos die), matching the fixtures.

  EchoServer(const std::string &certFile, const std::string &keyFile)
  {
    TransportConfig cfg;
    cfg.serverTls.enabled = true;
    cfg.serverTls.defaultMode = TlsMode::Server;
    cfg.serverTls.certFile = certFile;
    cfg.serverTls.keyFile = keyFile;
    tx = std::make_unique<TcpEngine>(cfg);
    iora::network::detail::EngineBase::Callbacks cbs{};
    cbs.onData = [this](SessionId sid, iora::core::BufferView data, std::chrono::steady_clock::time_point)
    { tx->send(sid, data.data(), data.size()); };
    cbs.onClose = [this](SessionId, const TransportErrorInfo &e)
    {
      std::lock_guard<std::mutex> lk(m);
      closeInfos.push_back(e);
    };
    tx->setCallbacks(cbs);
    REQUIRE(tx->start().isOk());
    port = testnet::addLoopbackListeners(*tx, SOCK_STREAM, TlsMode::Server);
  }

  ~EchoServer()
  {
    if (tx)
    {
      tx->stop();
    }
  }

  std::vector<TransportErrorInfo> closes()
  {
    std::lock_guard<std::mutex> lk(m);
    return closeInfos;
  }
};

} // namespace

// ============================================================================
// Phase 3: the SIGPIPE-guard lock. A write to a TLS socket after a local SHUT_WR returns
// EPIPE and (absent the per-thread block) raises a process-killing SIGPIPE. The engine
// must instead surface a clean onClose(TLSIO, EPIPE) and keep running.
// ============================================================================
TEST_CASE("TLS write-after-close surfaces TLSIO/EPIPE, no SIGPIPE, engine survives",
          "[tls][sigpipe]")
{
  requireSigpipeDefaultAndUnblocked();

  std::string certFile, keyFile;
  requireCerts(certFile, keyFile);

  // Declared BEFORE the engine owners so a REQUIRE that throws mid-setup cannot destroy
  // this atomic before ~Client's stop()-drain fires the onClose hook that writes it.
  std::atomic<int> sigpipePendingSeen{-1};

  SinkServer server(true, certFile, keyFile);
  Client client(true, nullptr, &makeFaultEngine);
  auto *fe = static_cast<FaultEngine *>(client.tx.get());
  REQUIRE(client.tx->start().isOk());

  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
  REQUIRE(cr.isOk());
  const SessionId sid = cr.value();
  REQUIRE(waitFor([&] { return client.connectCount.load() == 1; }));

  // Capture sigpending(SIGPIPE) in onClose (I/O thread) to prove the signal was actually
  // generated by the write and absorbed by the block. Published into sigpipePendingSeen;
  // main waits on THAT value (not on the fixture close count, which is updated and
  // released before this hook runs -> no happens-before). sid-filtered one-shot.
  client.setOnCloseHook(
    [&, sid](SessionId s, const TransportErrorInfo &)
    {
      if (s != sid)
      {
        return;
      }
      sigset_t p{};
      ::sigpending(&p);
      sigpipePendingSeen.store(sigismember(&p, SIGPIPE));
    });

  // Arm the one-shot SHUT_WR for this session, then drive a write through the engine.
  fe->shutWrTarget.store(sid);
  REQUIRE(client.tx->send(sid, "x", 1));

  REQUIRE(waitFor([&] { return client.closesFor(sid) == 1; }));
  REQUIRE(fe->shutWrFired.load());
  REQUIRE(fe->shutWrFdOk.load());

  const TransportErrorInfo info = client.closeInfo(sid);
  REQUIRE(info.code == TransportError::TLSIO);
  REQUIRE(info.sysErrno == EPIPE); // pinned to OpenSSL 3.x (SSL_ERROR_SYSCALL + EPIPE)
  REQUIRE(info.message == iora::core::errnoMessage(EPIPE)); // write-side ERR_LIB_SYS branch
  REQUIRE(waitFor([&] { return sigpipePendingSeen.load() != -1; }));
  REQUIRE(sigpipePendingSeen.load() == 1);

  // Engine is still ALIVE (not merely isRunning()==true, which stays set after a loop
  // exception): a SECOND session ON THE SAME engine completes a full TLS round trip. The
  // one-shot SHUT_WR hook was already consumed (shutWrTarget==0), so it is inert here.
  auto cr2 = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
  REQUIRE(cr2.isOk());
  REQUIRE(waitFor([&] { return client.connectCount.load() == 2; }));
  REQUIRE(client.tx->send(cr2.value(), "alive|", 6));
  REQUIRE(waitFor([&] { return server.data().find("alive|") != std::string::npos; }));
}

// ============================================================================
// Phase 3b.5 (deterministic single-fix lock, RM-4(d)): a stale ERR_LIB_SYS entry on the
// I/O thread's error queue must not make SSL_get_error misclassify a healthy session's
// WANT_READ. The ERR_clear_error() added before SSL_read (after the beforeSslRead hook)
// wipes the injected entry, so the session survives.
// MUTATION: remove the ERR_clear_error() before SSL_read in readAvail -> this client is
// closed with TLSIO instead of staying open.
// ============================================================================
TEST_CASE("stale OpenSSL error-queue entry does not spuriously close a healthy TLS session",
          "[tls][sigpipe]")
{
  requireSigpipeDefaultAndUnblocked();

  std::string certFile, keyFile;
  requireCerts(certFile, keyFile);

  SinkServer server(true, certFile, keyFile);
  Client client(true, nullptr, &makeFaultEngine);
  auto *fe = static_cast<FaultEngine *>(client.tx.get());
  REQUIRE(client.tx->start().isOk());

  // Arm BEFORE connect so the first post-handshake readAvail (this engine's only session)
  // deterministically injects the stale entry ahead of the WANT_READ read it performs --
  // no post-connect arming race.
  fe->errInjectArmed.store(true);

  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
  REQUIRE(cr.isOk());
  const SessionId sid = cr.value();

  REQUIRE(waitFor([&] { return client.connectCount.load() == 1; }));
  REQUIRE(waitFor([&] { return fe->errInjectFired.load(); }));

  // Post-fix: the injected entry is cleared before SSL_read, so the WANT_READ is classified
  // correctly and the session is NOT closed. Prove it is still open and usable.
  REQUIRE(client.tx->send(sid, "still-open|", 11));
  REQUIRE(waitFor([&] { return server.data().find("still-open|") != std::string::npos; }));
  REQUIRE(client.closesFor(sid) == 0);
}

// ============================================================================
// Phase 3b.5 (realistic cross-session POSITIVE integration test, RM-4(a)-(c)): two TLS
// sessions A and B on ONE client engine (one I/O thread, one shared OpenSSL error queue).
// B handshakes and exchanges first; a REAL SSL_write EPIPE is then forced on A (SHUT_WR);
// B must then still read a fresh echo with NO handshake in between.
//
// This is a POSITIVE end-to-end confirmation that a real sibling failure does not disrupt
// a healthy session -- NOT a single-mutation discriminator. Empirically (verified in this
// session) B survives even under a full Phase-3b revert: A's real SHUT_WR failure happens
// to clean up its own error-queue residue through the close path, so no B-affecting residue
// remains. The residue->misclassification HAZARD is real and is locked by the deterministic
// injection test above (which proves the per-op ERR_clear_error of 3b.1 is load-bearing).
// 3b.2 (full-drain) and 3b.3 (quiet-shutdown / SSL_is_init_finished gate) are defense-in-
// depth over 3b.1 plus the SSL_get_error(3) / SSL_shutdown(3) contract; 3b.3's clean-close
// behavior is locked by the close_notify test below.
// ============================================================================
TEST_CASE("one session's fatal TLS error does not close a sibling on the same I/O thread",
          "[tls][sigpipe]")
{
  requireSigpipeDefaultAndUnblocked();

  std::string certFile, keyFile;
  requireCerts(certFile, keyFile);

  EchoServer echo(certFile, keyFile);

  // Observation state is declared BEFORE the engine so it outlives the engine's teardown
  // drain: if a REQUIRE throws, ~FaultEngine's stop() fires onClose into these locals, so
  // they must still be alive. The StopGuard then stop()s (joins the I/O thread) BEFORE
  // ~FaultEngine runs, which also avoids a vptr race on the overridden hooks during
  // destruction. (reviewers round 2; cf. reference_iora_test_fixture_teardown_uaf)
  std::mutex m;
  std::map<SessionId, int> connects, closes;
  std::map<SessionId, std::string> rx;

  TransportConfig cfg;
  cfg.clientTls.enabled = true;
  cfg.clientTls.defaultMode = TlsMode::Client;
  cfg.clientTls.verifyPeer = false;
  FaultEngine fe(cfg);
  struct StopGuard
  {
    TcpEngine &e;
    ~StopGuard() { e.stop(); }
  } stopGuard{fe};

  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onConnect = [&](SessionId sid, const TransportAddress &)
  { std::lock_guard<std::mutex> lk(m); connects[sid]++; };
  cbs.onClose = [&](SessionId sid, const TransportErrorInfo &)
  { std::lock_guard<std::mutex> lk(m); closes[sid]++; };
  cbs.onData = [&](SessionId sid, iora::core::BufferView d, std::chrono::steady_clock::time_point)
  { std::lock_guard<std::mutex> lk(m); rx[sid].append(reinterpret_cast<const char *>(d.data()), d.size()); };
  fe.setCallbacks(cbs);
  REQUIRE(fe.start().isOk());

  auto ca = fe.connect("127.0.0.1", echo.port, TlsMode::Client);
  auto cb = fe.connect("127.0.0.1", echo.port, TlsMode::Client);
  REQUIRE(ca.isOk());
  REQUIRE(cb.isOk());
  const SessionId A = ca.value();
  const SessionId B = cb.value();

  auto connected = [&](SessionId s)
  { std::lock_guard<std::mutex> lk(m); return connects[s] == 1; };
  REQUIRE(waitFor([&] { return connected(A) && connected(B); }));

  // B exchanges first -> established and proven healthy (RM-4(b)).
  REQUIRE(fe.send(B, "b1|", 3));
  REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(m); return rx[B].find("b1|") != std::string::npos; }));

  // Force A's fatal TLSIO: a real SSL_write EPIPE (write after our own SHUT_WR), closed via
  // the real closeTlsIo path, with NO handshake in between (RM-4(c)).
  fe.shutWrTarget.store(A);
  REQUIRE(fe.send(A, "a|", 2));
  REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(m); return closes[A] == 1; }));

  // Positive confirmation (see header): B must still read a fresh echo and stay open after a
  // real sibling failure. This is NOT a 3b mutation discriminator -- B survives even under a
  // full 3b revert, because A's real failure cleans its own residue through the close path;
  // the deterministic injection test above is the mutation-proven lock for 3b.1.
  REQUIRE(fe.send(B, "b2|", 3));
  REQUIRE(waitFor([&] { std::lock_guard<std::mutex> lk(m); return rx[B].find("b2|") != std::string::npos; }));
  {
    std::lock_guard<std::mutex> lk(m);
    REQUIRE(closes[B] == 0);
  }
}

// ============================================================================
// Phase 3b (close_notify regression, review M-3): the new SSL_is_init_finished gate in
// sslTeardown must NOT suppress close_notify on a clean, init-finished close. A client
// that app-closes an established TLS session sends close_notify, which the peer observes as
// an orderly ZERO_RETURN -> PeerClosed("TLS peer closed"), distinct from a bare-FIN TLSIO.
// ============================================================================
TEST_CASE("clean TLS close still sends close_notify (peer sees PeerClosed)", "[tls][sigpipe]")
{
  requireSigpipeDefaultAndUnblocked();

  std::string certFile, keyFile;
  requireCerts(certFile, keyFile);

  // SinkServer (no echo-back), so closing the client cannot race a server echo into a
  // closing socket (which could surface as an RST/TLSIO instead of the clean close_notify).
  SinkServer server(true, certFile, keyFile);
  Client client(true);
  REQUIRE(client.tx->start().isOk());

  auto cr = client.tx->connect("127.0.0.1", server.port, TlsMode::Client);
  REQUIRE(cr.isOk());
  const SessionId sid = cr.value();
  REQUIRE(waitFor([&] { return client.connectCount.load() == 1; }));

  // Exchange one message and WAIT for the server to receive it, so the session is proven
  // fully established (and the server past its handshake) before the clean close.
  REQUIRE(client.tx->send(sid, "hi|", 3));
  REQUIRE(waitFor([&] { return server.data().find("hi|") != std::string::npos; }));

  // Clean per-session close -> sslTeardown (init-finished, not quiet) -> SSL_shutdown sends
  // close_notify on the live fd.
  REQUIRE(client.tx->close(sid));

  REQUIRE(waitFor([&] { return !server.closeInfoList().empty(); }));
  const auto infos = server.closeInfoList();
  REQUIRE(infos.front().code == TransportError::PeerClosed);
  REQUIRE(infos.front().message == "TLS peer closed"); // the ZERO_RETURN (close_notify) path
}
