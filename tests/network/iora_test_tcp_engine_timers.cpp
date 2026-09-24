#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/network/detail/tcp_engine.hpp"
#include "iora_test_net_utils.hpp"
#include "network/tcp_connect_test_fixtures.hpp"
#include "test_helpers.hpp"

using namespace std::chrono_literals;
using TcpEngine = iora::network::TcpEngine;
using TransportConfig = iora::network::TransportConfig;
using TransportAddress = iora::network::TransportAddress;
using TransportErrorInfo = iora::network::TransportErrorInfo;
using TransportError = iora::network::TransportError;
using TlsMode = iora::network::TlsMode;
using SessionId = iora::network::SessionId;

TEST_CASE("High-resolution timer configuration", "[shared_transport][timers]")
{
  TransportConfig cfg{};
  cfg.enableHighResolutionTimers = true;
  cfg.connectTimeout = 500ms;
  cfg.handshakeTimeout = 1000ms;
  cfg.writeStallTimeout = 750ms;

  TcpEngine transport(cfg);
  REQUIRE(transport.start().isOk());

  // Verify the configuration is set correctly
  REQUIRE(cfg.enableHighResolutionTimers == true);
  REQUIRE(cfg.connectTimeout == 500ms);
  REQUIRE(cfg.handshakeTimeout == 1000ms);
  REQUIRE(cfg.writeStallTimeout == 750ms);

  transport.stop();
}

TEST_CASE("Legacy timer fallback when high-resolution disabled", "[shared_transport][timers]")
{
  TransportConfig cfg{};
  cfg.enableHighResolutionTimers = false;
  cfg.connectTimeout = 1000ms;
  cfg.handshakeTimeout = 2000ms;
  cfg.gcInterval = 1s;

  TcpEngine transport(cfg);
  REQUIRE(transport.start().isOk());

  // Verify legacy configuration
  REQUIRE(cfg.enableHighResolutionTimers == false);
  REQUIRE(cfg.gcInterval == 1s);

  transport.stop();
}

TEST_CASE("SIP-optimized timeout configuration", "[shared_transport][timers][sip]")
{
  // Test SIP-specific timeout configurations for DNS/SRV failover
  TransportConfig sipCfg{};
  sipCfg.enableHighResolutionTimers = true;
  sipCfg.connectTimeout = 2000ms;    // 2s per SRV record
  sipCfg.handshakeTimeout = 3000ms;  // 3s for TLS handshake
  sipCfg.writeStallTimeout = 1000ms; // 1s write timeout

  // Verify SIP-optimized timeouts are suitable for DNS/SRV failover
  REQUIRE(sipCfg.connectTimeout == 2000ms);
  REQUIRE(sipCfg.handshakeTimeout == 3000ms);
  REQUIRE(sipCfg.writeStallTimeout == 1000ms);

  // These timeouts are suitable for SIP DNS/SRV failover scenarios
  // where we need fast failover through multiple records
  REQUIRE(sipCfg.connectTimeout <= 5000ms);    // Fast enough for SRV failover
  REQUIRE(sipCfg.handshakeTimeout <= 5000ms);  // Fast TLS establishment
  REQUIRE(sipCfg.writeStallTimeout <= 2000ms); // Quick write failure detection

  TcpEngine sipTransport(sipCfg);

  REQUIRE(sipTransport.start().isOk());
  sipTransport.stop();
}

TEST_CASE("Connect timeout with high-resolution timer", "[shared_transport][timers][integration]")
{
  // A loopback listener with a full accept queue: the SYN is dropped, so the
  // connect deterministically stays in the TCP phase until the timeout.
  tcptest::Blackhole bh;
  if (!tcptest::fillOrSkip(bh))
  {
    return;
  }

  std::atomic<bool> connectionFailed{false};
  std::atomic<bool> connected{false};
  std::string lastErrorMessage;
  TransportError lastErrorCode{TransportError::None};
  int lastSysErrno{0};

  TransportConfig cfg{};
  cfg.enableHighResolutionTimers = true;
  cfg.connectTimeout = 100ms; // Very short timeout for testing

  TcpEngine transport(cfg);

  iora::network::detail::EngineBase::Callbacks cbs{};
  cbs.onConnect = [&](SessionId, const TransportAddress &) { connected = true; };

  cbs.onClose = [&](SessionId, const TransportErrorInfo &err)
  {
    lastErrorMessage = err.message;
    lastErrorCode = err.code;
    lastSysErrno = err.sysErrno;
    connectionFailed = true;
    std::cout << "Connection closed: " << err.message << " (code " << static_cast<int>(err.code)
              << ")\n";
  };

  transport.setCallbacks(cbs);
  REQUIRE(transport.start().isOk());

  auto cr = transport.connect("127.0.0.1", bh.lst.port, TlsMode::None);
  REQUIRE(cr.isOk());

  // Wait for timeout to occur (should be around 100ms)
  auto start = std::chrono::steady_clock::now();

  for (int i = 0; i < 50 && !connectionFailed && !connected; ++i)
  {
    std::this_thread::sleep_for(10ms);
  }

  auto elapsed = std::chrono::steady_clock::now() - start;

  REQUIRE(connectionFailed);
  REQUIRE_FALSE(connected);
  REQUIRE(elapsed < 500ms);
  REQUIRE(lastErrorCode == TransportError::Connect);
  REQUIRE(lastSysErrno == ETIMEDOUT);
  REQUIRE(lastErrorMessage == "Connect timeout");

  transport.stop();
}
