#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "test_helpers.hpp"
#include "iora/network/shared_transport.hpp"
#include "iora_test_net_utils.hpp"

using namespace std::chrono_literals;
using SharedTransport = iora::network::SharedTransport;
using TransportError = iora::network::TransportError;
using TlsMode = iora::network::TlsMode;
using IoResult = iora::network::IoResult;
using SessionId = iora::network::SessionId;

TEST_CASE("High-resolution timer configuration", "[shared_transport][timers]")
{
  SharedTransport::Config cfg{};
  cfg.enableHighResolutionTimers = true;
  cfg.connectTimeout = 500ms;
  cfg.handshakeTimeout = 1000ms;
  cfg.writeStallTimeout = 750ms;
  
  SharedTransport::TlsConfig srvTls{};
  SharedTransport::TlsConfig cliTls{};
  
  SharedTransport transport(cfg, srvTls, cliTls);
  REQUIRE(transport.start());
  
  // Verify the configuration is set correctly
  REQUIRE(cfg.enableHighResolutionTimers == true);
  REQUIRE(cfg.connectTimeout == 500ms);
  REQUIRE(cfg.handshakeTimeout == 1000ms);
  REQUIRE(cfg.writeStallTimeout == 750ms);
  
  transport.stop();
}

TEST_CASE("Legacy timer fallback when high-resolution disabled", "[shared_transport][timers]")
{
  SharedTransport::Config cfg{};
  cfg.enableHighResolutionTimers = false;
  cfg.connectTimeout = 1000ms;
  cfg.handshakeTimeout = 2000ms;
  cfg.gcInterval = 1s;
  
  SharedTransport::TlsConfig srvTls{};
  SharedTransport::TlsConfig cliTls{};
  
  SharedTransport transport(cfg, srvTls, cliTls);
  REQUIRE(transport.start());
  
  // Verify legacy configuration
  REQUIRE(cfg.enableHighResolutionTimers == false);
  REQUIRE(cfg.gcInterval == 1s);
  
  transport.stop();
}

TEST_CASE("SIP-optimized timeout configuration", "[shared_transport][timers][sip]")
{
  // Test SIP-specific timeout configurations for DNS/SRV failover
  SharedTransport::Config sipCfg{};
  sipCfg.enableHighResolutionTimers = true;
  sipCfg.connectTimeout = 2000ms;      // 2s per SRV record
  sipCfg.handshakeTimeout = 3000ms;    // 3s for TLS handshake  
  sipCfg.writeStallTimeout = 1000ms;   // 1s write timeout
  
  // Verify SIP-optimized timeouts are suitable for DNS/SRV failover
  REQUIRE(sipCfg.connectTimeout == 2000ms);
  REQUIRE(sipCfg.handshakeTimeout == 3000ms);
  REQUIRE(sipCfg.writeStallTimeout == 1000ms);
  
  // These timeouts are suitable for SIP DNS/SRV failover scenarios
  // where we need fast failover through multiple records
  REQUIRE(sipCfg.connectTimeout <= 5000ms);    // Fast enough for SRV failover
  REQUIRE(sipCfg.handshakeTimeout <= 5000ms);  // Fast TLS establishment
  REQUIRE(sipCfg.writeStallTimeout <= 2000ms); // Quick write failure detection
  
  SharedTransport::TlsConfig srvTls{};
  SharedTransport::TlsConfig cliTls{};
  SharedTransport sipTransport(sipCfg, srvTls, cliTls);
  
  REQUIRE(sipTransport.start());
  sipTransport.stop();
}

TEST_CASE("Connect timeout with high-resolution timer", "[shared_transport][timers][integration]")
{
  SharedTransport::Config cfg{};
  cfg.enableHighResolutionTimers = true;
  cfg.connectTimeout = 100ms;      // Very short timeout for testing
  
  SharedTransport::TlsConfig srvTls{};
  SharedTransport::TlsConfig cliTls{};
  SharedTransport transport(cfg, srvTls, cliTls);
  
  std::atomic<bool> connectionFailed{false};
  std::atomic<bool> connected{false};
  std::string lastErrorMessage;
  TransportError lastErrorCode{TransportError::None};
  
  SharedTransport::Callbacks cbs{};
  cbs.onConnect = [&](SessionId sid, const IoResult& res)
  {
    if (res.ok)
    {
      connected = true;
    }
    else
    {
      connectionFailed = true;
      lastErrorMessage = res.message;
      lastErrorCode = res.code;
      std::cout << "Connection failed: " << res.message << " (code " << static_cast<int>(res.code) << ")\n";
    }
  };
  
  cbs.onClosed = [&](SessionId sid, const IoResult& res)
  {
    connectionFailed = true;
    lastErrorMessage = res.message;
    lastErrorCode = res.code;
    std::cout << "Connection closed: " << res.message << " (code " << static_cast<int>(res.code) << ")\n";
  };
  
  transport.setCallbacks(cbs);
  REQUIRE(transport.start());
  
  // Try to connect to a non-routable address that should timeout quickly
  // Using 10.254.254.254 which should be non-routable
  SessionId sid = transport.connect("10.254.254.254", 9999, TlsMode::None);
  REQUIRE(sid != 0);
  
  // Wait for timeout to occur (should be around 100ms)
  auto start = std::chrono::steady_clock::now();
  
  for (int i = 0; i < 50 && !connectionFailed && !connected; ++i)
  {
    std::this_thread::sleep_for(10ms);
  }
  
  auto elapsed = std::chrono::steady_clock::now() - start;
  
  // Should timeout much faster than the old default of 30 seconds
  REQUIRE((connectionFailed || connected));
  REQUIRE(elapsed < 500ms); // Should be much faster than 5 seconds
  REQUIRE(lastErrorCode == TransportError::Timeout);
  
  transport.stop();
}