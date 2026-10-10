// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for IoraService::applyConfig TLS gating (tracker 2026-09-24-11, P0).
//
// The bug: applyConfig enabled server TLS only when certFile+keyFile+caFile were
// ALL set, so server-auth-only TLS (cert+key, no CA) silently served PLAINTEXT,
// and partial/mis-configured TLS also silently downgraded. The fix is fail-closed:
// enable TLS when cert+key are set (CA required only for mTLS), and throw loudly on
// any partially-configured TLS instead of downgrading. Every case is driven through
// IoraService::init(Config) — the path that carries the defect — and the TLS cases
// are exercised at the handshake level, not as pure unit logic.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include "iora_test_net_utils.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace iora::test;

namespace
{
const std::string kCertFile =
  std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_cert.pem";
const std::string kKeyFile =
  std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_key.pem";

// Minimal valid Config; each case picks its own port + state/log paths.
iora::IoraService::Config baseConfig(int port, const std::string &stateFile,
                                     const std::string &logFile)
{
  iora::IoraService::Config cfg;
  cfg.server.port = port;
  cfg.state.file = stateFile;
  cfg.log.file = logFile;
  cfg.log.level = "error";
  return cfg;
}

// Shut the singleton down at scope exit. NOTE: after a FAILED init, shutdown() is
// currently a no-op — IoraService::shutdown() early-returns on !_isRunning and
// _isRunning is only set at the end of applyConfig (tracked: failed-init lifecycle
// defect, iora 2026-10-01 followups). So on the throwing cases this guard does not
// release the singleton; the suite tolerates that only because each subsequent
// init() overwrites the stale members. It DOES clean up the successful cases.
struct AlwaysShutdown
{
  ~AlwaysShutdown()
  {
    try
    {
      iora::IoraService::shutdown();
    }
    catch (...)
    {
    }
  }
};

// Holds a TCP LISTEN socket on a port so a subsequent server bind on the same port
// fails in WebhookServer::start(). This relies on the holder NOT setting
// SO_REUSEPORT: the server listener sets SO_REUSEADDR|SO_REUSEPORT, and on Linux a
// port can be shared only if BOTH sockets set SO_REUSEPORT — so the server's bind
// gets EADDRINUSE here. (Do not add SO_REUSEPORT to this holder.)
struct PortHolder
{
  int fd{-1};
  explicit PortHolder(int port)
  {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 ||
        ::listen(fd, 1) != 0)
    {
      ::close(fd); // avoid leaking the fd if the REQUIRE below fails
      fd = -1;
      FAIL("PortHolder: could not bind/listen on the chosen port");
    }
  }
  ~PortHolder()
  {
    if (fd >= 0)
      ::close(fd);
  }
  PortHolder(const PortHolder &) = delete;
  PortHolder &operator=(const PortHolder &) = delete;
};

// RAII: install a log-capturing external handler, restore file logging on exit.
// While installed the handler is the sole sink (Logger contract), so we capture
// every record at or above the active level into a mutex-guarded buffer.
struct LogCaptureGuard
{
  std::vector<std::string> messages; // raw messages
  std::mutex mutex;
  LogCaptureGuard()
  {
    iora::core::Logger::setExternalHandler(
      [this](iora::core::Logger::Level, const std::string &, const std::string &raw)
      {
        std::lock_guard<std::mutex> lock(mutex);
        messages.push_back(raw);
      });
  }
  ~LogCaptureGuard() { iora::core::Logger::clearExternalHandler(); }
  bool sawContaining(const std::string &needle)
  {
    iora::core::Logger::flush();
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto &m : messages)
    {
      if (m.find(needle) != std::string::npos)
        return true;
    }
    return false;
  }
};

bool tcpConnectSucceeds(int port)
{
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return false;
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  const bool ok = ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
  ::close(fd);
  return ok;
}

// Poll until the listener accepts a TCP connection (replaces fixed sleeps).
void waitForListener(int port, int timeoutMs = 3000)
{
  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (tcpConnectSucceeds(port))
      return;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
}

// Register a probe route and wait for the listener to accept connections.
void installProbe(iora::IoraService &svc, int port)
{
  REQUIRE(svc.webhookServer() != nullptr);
  svc.webhookServer()->onJsonGet("/tls-probe",
                                 [](const iora::parsers::Json &) -> iora::parsers::Json
                                 {
                                   auto obj = iora::parsers::Json::object();
                                   obj["tls"] = true;
                                   return obj;
                                 });
  waitForListener(port);
}

// A real HTTPS GET (peer verification off — the fixture cert is self-signed).
// Returns true only if the TLS handshake completed AND the probe body came back.
bool httpsProbeSucceeds(int port)
{
  iora::network::HttpClient client;
  iora::network::HttpClient::TlsConfig tls;
  tls.verifyPeer = false;
  client.setTlsConfig(tls);
  try
  {
    auto res = client.get("https://127.0.0.1:" + std::to_string(port) + "/tls-probe");
    if (!res.success())
      return false;
    auto json = iora::network::HttpClient::parseJsonOrThrow(res);
    return json["tls"] == true;
  }
  catch (const std::exception &)
  {
    return false;
  }
}

// A plaintext (non-TLS) GET to the port. On a TLS listener this must NOT succeed.
bool plaintextProbeSucceeds(int port)
{
  iora::network::HttpClient client;
  try
  {
    auto res = client.get("http://127.0.0.1:" + std::to_string(port) + "/tls-probe");
    return res.success();
  }
  catch (const std::exception &)
  {
    return false;
  }
}

std::string writeTempFile(TempDirManager &tmp, const std::string &name,
                          const std::string &content)
{
  const std::string path = tmp.filePath(name);
  std::ofstream os(path, std::ios::binary);
  os << content;
  return path;
}
} // namespace

// --- T1: server-auth-only TLS (cert+key, no CA) — the primary regression test ---
TEST_CASE("TLS T1 server-auth-only brings up TLS and refuses plaintext",
          "[iora][tls][config]")
{
  REQUIRE(std::filesystem::exists(kCertFile));
  REQUIRE(std::filesystem::exists(kKeyFile));
  TempDirManager tmp;
  const int port = testnet::getFreePortTCP();
  auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
  cfg.server.tls.certFile = kCertFile;
  cfg.server.tls.keyFile = kKeyFile;
  // no caFile, requireClientCert unset → server-auth-only TLS must come up.

  iora::IoraService::init(cfg);
  auto &svc = iora::IoraService::instanceRef();
  AlwaysShutdown guard;
  installProbe(svc, port);

  REQUIRE(httpsProbeSucceeds(port));
  REQUIRE_FALSE(plaintextProbeSucceeds(port)); // no silent plaintext downgrade
}

// --- T2: cert+key+CA, requireClientCert=false → TLS up (CA present but ignored) --
TEST_CASE("TLS T2 cert+key+CA without mTLS brings up TLS", "[iora][tls][config]")
{
  TempDirManager tmp;
  const int port = testnet::getFreePortTCP();
  auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
  cfg.server.tls.certFile = kCertFile;
  cfg.server.tls.keyFile = kKeyFile;
  cfg.server.tls.caFile = kCertFile; // self-signed cert stands in as a CA PEM
  cfg.server.tls.requireClientCert = false;

  iora::IoraService::init(cfg);
  auto &svc = iora::IoraService::instanceRef();
  AlwaysShutdown guard;
  installProbe(svc, port);

  REQUIRE(httpsProbeSucceeds(port));
  REQUIRE_FALSE(plaintextProbeSucceeds(port));
}

// --- T2b: caFile = nonexistent path, mTLS off → CA ignored, TLS still up (L3) ----
TEST_CASE("TLS T2b bad caFile path is ignored when mTLS is off", "[iora][tls][config]")
{
  TempDirManager tmp;
  const int port = testnet::getFreePortTCP();
  auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
  cfg.server.tls.certFile = kCertFile;
  cfg.server.tls.keyFile = kKeyFile;
  cfg.server.tls.caFile = tmp.filePath("does_not_exist_ca.pem"); // never created
  cfg.server.tls.requireClientCert = false;

  iora::IoraService::init(cfg);
  auto &svc = iora::IoraService::instanceRef();
  AlwaysShutdown guard;
  installProbe(svc, port);

  REQUIRE(httpsProbeSucceeds(port)); // a bad CA path is silently accepted when mTLS off
  REQUIRE_FALSE(plaintextProbeSucceeds(port));
}

// --- T3: mTLS requested, no CA → init THROWS at enableTls, nothing listening ------
TEST_CASE("TLS T3 requireClientCert without CA fails closed", "[iora][tls][config]")
{
  TempDirManager tmp;
  const int port = testnet::getFreePortTCP();
  auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
  cfg.server.tls.certFile = kCertFile;
  cfg.server.tls.keyFile = kKeyFile;
  cfg.server.tls.requireClientCert = true; // no caFile

  AlwaysShutdown guard;
  REQUIRE_THROWS_WITH(iora::IoraService::init(cfg),
                      Catch::Matchers::Contains("caFile is not set"));
  REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
}

// --- T4/T5/T6/T7: partial configs fail closed at the EARLY predicate check --------
TEST_CASE("TLS T4 cert only fails closed", "[iora][tls][config]")
{
  TempDirManager tmp;
  auto cfg = baseConfig(testnet::getFreePortTCP(), tmp.filePath("state.json"),
                        tmp.filePath("log"));
  cfg.server.tls.certFile = kCertFile; // no key
  AlwaysShutdown guard;
  REQUIRE_THROWS_WITH(iora::IoraService::init(cfg),
                      Catch::Matchers::Contains("partially configured") &&
                        Catch::Matchers::Contains("keyFile"));
  REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
}

TEST_CASE("TLS T5 key only fails closed", "[iora][tls][config]")
{
  TempDirManager tmp;
  auto cfg = baseConfig(testnet::getFreePortTCP(), tmp.filePath("state.json"),
                        tmp.filePath("log"));
  cfg.server.tls.keyFile = kKeyFile; // no cert
  AlwaysShutdown guard;
  REQUIRE_THROWS_WITH(iora::IoraService::init(cfg),
                      Catch::Matchers::Contains("partially configured") &&
                        Catch::Matchers::Contains("certFile"));
  REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
}

TEST_CASE("TLS T6 caFile only fails closed", "[iora][tls][config]")
{
  TempDirManager tmp;
  auto cfg = baseConfig(testnet::getFreePortTCP(), tmp.filePath("state.json"),
                        tmp.filePath("log"));
  cfg.server.tls.caFile = kCertFile; // no cert/key
  AlwaysShutdown guard;
  REQUIRE_THROWS_WITH(iora::IoraService::init(cfg),
                      Catch::Matchers::Contains("partially configured"));
  REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
}

TEST_CASE("TLS T7 requireClientCert only fails closed", "[iora][tls][config]")
{
  TempDirManager tmp;
  auto cfg = baseConfig(testnet::getFreePortTCP(), tmp.filePath("state.json"),
                        tmp.filePath("log"));
  cfg.server.tls.requireClientCert = true; // no paths at all
  AlwaysShutdown guard;
  REQUIRE_THROWS_WITH(iora::IoraService::init(cfg),
                      Catch::Matchers::Contains("partially configured"));
  REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
}

// --- T8: intentional plaintext (nothing set; and requireClientCert=false alone) --
TEST_CASE("TLS T8 no TLS requested serves plaintext (no throw)", "[iora][tls][config]")
{
  SECTION("nothing set")
  {
    TempDirManager tmp;
    const int port = testnet::getFreePortTCP();
    auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
    iora::IoraService::init(cfg);
    auto &svc = iora::IoraService::instanceRef();
    AlwaysShutdown guard;
    installProbe(svc, port);
    REQUIRE(svc.webhookServer() != nullptr);
    REQUIRE(plaintextProbeSucceeds(port));
  }
  SECTION("requireClientCert=false alone stays not-requested")
  {
    TempDirManager tmp;
    const int port = testnet::getFreePortTCP();
    auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
    cfg.server.tls.requireClientCert = false; // must NOT force a fail-closed throw
    iora::IoraService::init(cfg);
    auto &svc = iora::IoraService::instanceRef();
    AlwaysShutdown guard;
    installProbe(svc, port);
    REQUIRE(svc.webhookServer() != nullptr);
    REQUIRE(plaintextProbeSucceeds(port));
  }
}

// --- T9: non-PEM cert → throws at the enableTls validation stage ------------------
TEST_CASE("TLS T9 non-PEM cert fails closed at enableTls", "[iora][tls][config]")
{
  TempDirManager tmp;
  const std::string junkCert = writeTempFile(tmp, "junk_cert.pem", "not a pem file\n");
  auto cfg = baseConfig(testnet::getFreePortTCP(), tmp.filePath("state.json"),
                        tmp.filePath("log"));
  cfg.server.tls.certFile = junkCert; // set + non-empty → complete, but invalid
  cfg.server.tls.keyFile = kKeyFile;
  AlwaysShutdown guard;
  REQUIRE_THROWS_WITH(iora::IoraService::init(cfg),
                      Catch::Matchers::Contains("certFile") &&
                        Catch::Matchers::Contains("PEM format"));
  REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
}

// --- T9b: valid-PEM but MISMATCHED cert/key (swapped) → throws in start() ----------
//   Both files are valid PEM so enableTls (generic "-----BEGIN" + size sniff) passes;
//   SSL_CTX_use_certificate_file / check_private_key then fails in WebhookServer::
//   start(). Pins the start()-catch _webhookServer.reset() (tracker MED-1, as spec'd).
TEST_CASE("TLS T9b mismatched cert/key fails in start(), no half-built server",
          "[iora][tls][config]")
{
  TempDirManager tmp;
  auto cfg = baseConfig(testnet::getFreePortTCP(), tmp.filePath("state.json"),
                        tmp.filePath("log"));
  cfg.server.tls.certFile = kKeyFile; // a key in the cert slot (valid PEM, wrong type)
  cfg.server.tls.keyFile = kCertFile; // a cert in the key slot
  AlwaysShutdown guard;
  REQUIRE_THROWS_AS(iora::IoraService::init(cfg), std::runtime_error);
  REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
}

// --- T9c: a start() bind failure (port held) → start()-catch reset (extra proof) --
TEST_CASE("TLS T9c start() bind failure leaves no half-built server",
          "[iora][tls][config]")
{
  TempDirManager tmp;
  const int port = testnet::getFreePortTCP();
  PortHolder hold(port); // occupy the port so the server bind/listen fails
  auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
  cfg.server.tls.certFile = kCertFile;
  cfg.server.tls.keyFile = kKeyFile;

  AlwaysShutdown guard;
  REQUIRE_THROWS_AS(iora::IoraService::init(cfg), std::runtime_error);
  REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
}

// --- T10: mTLS config brings the listener up (enforcement scoped to 2026-09-12-8) -
//   Assert ONLY that the listener comes up. Do NOT assert a cert-less handshake
//   succeeds — client-cert enforcement is owned by 2026-09-12-8, and encoding the
//   current no-enforcement behavior as expected would be a masked test.
TEST_CASE("TLS T10 mTLS config brings the listener up", "[iora][tls][config]")
{
  TempDirManager tmp;
  const int port = testnet::getFreePortTCP();
  auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
  cfg.server.tls.certFile = kCertFile;
  cfg.server.tls.keyFile = kKeyFile;
  cfg.server.tls.caFile = kCertFile; // self-signed cert as the client-CA PEM
  cfg.server.tls.requireClientCert = true;

  iora::IoraService::init(cfg);
  auto &svc = iora::IoraService::instanceRef();
  AlwaysShutdown guard;
  REQUIRE(svc.webhookServer() != nullptr);
  waitForListener(port);
  REQUIRE(tcpConnectSucceeds(port)); // listener up; no handshake assertion
}

// --- M1: empty-string semantics (empty == unset) ---------------------------------
TEST_CASE("TLS M1 empty strings are treated as unset", "[iora][tls][config]")
{
  SECTION("empty cert + set key is partial → fails closed")
  {
    TempDirManager tmp;
    auto cfg = baseConfig(testnet::getFreePortTCP(), tmp.filePath("state.json"),
                          tmp.filePath("log"));
    cfg.server.tls.certFile = ""; // empty == unset
    cfg.server.tls.keyFile = kKeyFile;
    AlwaysShutdown guard;
    REQUIRE_THROWS_WITH(iora::IoraService::init(cfg),
                        Catch::Matchers::Contains("partially configured") &&
                          Catch::Matchers::Contains("certFile"));
    REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
  }
  SECTION("all-empty TLS block is not-requested → plaintext, no throw")
  {
    TempDirManager tmp;
    const int port = testnet::getFreePortTCP();
    auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
    cfg.server.tls.certFile = "";
    cfg.server.tls.keyFile = "";
    cfg.server.tls.caFile = "";
    iora::IoraService::init(cfg);
    auto &svc = iora::IoraService::instanceRef();
    AlwaysShutdown guard;
    installProbe(svc, port);
    REQUIRE(svc.webhookServer() != nullptr);
    REQUIRE(plaintextProbeSucceeds(port));
  }
}

// --- L4: features.server=false + TLS requested → WARN, no throw, no server --------
TEST_CASE("TLS L4 server disabled with TLS set warns and does not throw",
          "[iora][tls][config]")
{
  TempDirManager tmp;
  auto cfg = baseConfig(testnet::getFreePortTCP(), tmp.filePath("state.json"),
                        tmp.filePath("log"));
  cfg.log.level = "warn";
  cfg.features.server = false;
  cfg.server.tls.certFile = kCertFile; // TLS requested but server disabled

  LogCaptureGuard logs;
  AlwaysShutdown guard;
  REQUIRE_NOTHROW(iora::IoraService::init(cfg));
  REQUIRE(iora::IoraService::instanceRef().webhookServer() == nullptr);
  REQUIRE(logs.sawContaining("features.server is disabled"));
}

// --- WARN: requireClientCert=true emits the mTLS-pending enforcement warning ------
TEST_CASE("TLS mTLS-pending WARN is emitted for requireClientCert",
          "[iora][tls][config]")
{
  TempDirManager tmp;
  const int port = testnet::getFreePortTCP();
  auto cfg = baseConfig(port, tmp.filePath("state.json"), tmp.filePath("log"));
  cfg.log.level = "warn";
  cfg.server.tls.certFile = kCertFile;
  cfg.server.tls.keyFile = kKeyFile;
  cfg.server.tls.caFile = kCertFile;
  cfg.server.tls.requireClientCert = true;

  LogCaptureGuard logs;
  AlwaysShutdown guard;
  iora::IoraService::init(cfg);
  REQUIRE(iora::IoraService::instanceRef().webhookServer() != nullptr);
  REQUIRE(logs.sawContaining("client-certificate enforcement is not yet active"));
}
