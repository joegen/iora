// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for the IoraService::init() rollback: a start that fails part-way must
// tear down what it built (listener, plugins, worker threads), release the
// singleton and rethrow the original exception. Also covers concurrent
// shutdown() calls reading the singleton through the locked peek.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include "../plugins/unload_teardown_control.hpp"
#include "iora_test_net_utils.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace iora::test;

namespace
{
const std::string kCertFile = std::string(IORA_TEST_RESOURCE_DIR) + "/tls-certs/test_tls_cert.pem";
const std::string kAppliedMessage = "applyConfig: Configuration applied";
const std::string kPluginName = "onunloadrecordplugin.so";

iora::IoraService::Config baseConfig(int port, TempDirManager &tmp)
{
  iora::IoraService::Config cfg;
  cfg.server.port = port;
  cfg.state.file = tmp.filePath("state.json");
  cfg.log.file = tmp.filePath("log");
  cfg.log.level = "error";
  return cfg;
}

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

void requireMembersNull(const iora::IoraService &svc)
{
  REQUIRE(svc.webhookServer() == nullptr);
  REQUIRE(svc.jsonFileStore() == nullptr);
  REQUIRE(svc.threadPool() == nullptr);
  REQUIRE(svc.stateStore() == nullptr);
  REQUIRE(svc.cache() == nullptr);
  REQUIRE(svc.configLoader() == nullptr);
}

class Socket
{
public:
  Socket() : _fd(::socket(AF_INET, SOCK_STREAM, 0)) {}
  ~Socket()
  {
    if (_fd >= 0)
    {
      ::close(_fd);
    }
  }
  Socket(const Socket &) = delete;
  Socket &operator=(const Socket &) = delete;
  int fd() const { return _fd; }

private:
  int _fd;
};

sockaddr_in loopbackAddr(int port)
{
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  return addr;
}

bool connectRefused(int port)
{
  Socket s;
  if (s.fd() < 0)
  {
    return false;
  }
  sockaddr_in addr = loopbackAddr(port);
  if (::connect(s.fd(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0)
  {
    return false;
  }
  return errno == ECONNREFUSED;
}

// Binds and listens WITHOUT SO_REUSEPORT. The server listener sets
// SO_REUSEADDR|SO_REUSEPORT, so this fails with EADDRINUSE while it is alive.
bool canListenWithoutReusePort(int port)
{
  Socket s;
  if (s.fd() < 0)
  {
    return false;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(static_cast<uint16_t>(port));
  return ::bind(s.fd(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0 &&
         ::listen(s.fd(), 1) == 0;
}

// Throws from the synchronous log path on the last applyConfig() message, which
// is logged after the plugins are loaded.
struct ThrowOnAppliedGuard
{
  ThrowOnAppliedGuard()
  {
    iora::core::Logger::setExternalHandler(
      [](iora::core::Logger::Level, const std::string &, const std::string &raw)
      {
        if (raw == kAppliedMessage)
        {
          throw std::runtime_error("injected failure after plugin load");
        }
      });
  }
  ~ThrowOnAppliedGuard() { iora::core::Logger::clearExternalHandler(); }
  ThrowOnAppliedGuard(const ThrowOnAppliedGuard &) = delete;
  ThrowOnAppliedGuard &operator=(const ThrowOnAppliedGuard &) = delete;
};
} // namespace

TEST_CASE("Failed init before server start releases the singleton", "[iora][init][rollback]")
{
  TempDirManager tmp;
  auto cfg = baseConfig(testnet::getFreePortTCP(), tmp);
  cfg.server.tls.certFile = kCertFile;

  AlwaysShutdown guard;
  auto held = iora::IoraService::instance();
  std::weak_ptr<iora::IoraService> weak = held;

  REQUIRE_THROWS_AS(iora::IoraService::init(cfg), std::runtime_error);
  REQUIRE(iora::IoraService::getInstancePtr() == nullptr);
  requireMembersNull(*held);

  REQUIRE_NOTHROW(iora::IoraService::shutdown());
  REQUIRE(iora::IoraService::getInstancePtr() == nullptr);
  requireMembersNull(*held);

  held.reset();
  REQUIRE(weak.expired());
}

TEST_CASE("Failed init after server start closes the listener", "[iora][init][rollback]")
{
  TempDirManager tmp;
  const int port = testnet::getFreePortTCP();
  auto cfg = baseConfig(port, tmp);
  cfg.log.async = true;
  cfg.modules.directory = "/tmp/" + std::string(300, 'a');

  AlwaysShutdown guard;
  auto held = iora::IoraService::instance();

  REQUIRE_THROWS_AS(iora::IoraService::init(cfg), std::filesystem::filesystem_error);
  REQUIRE(iora::IoraService::getInstancePtr() == nullptr);
  requireMembersNull(*held);

  REQUIRE(connectRefused(port));
  REQUIRE(canListenWithoutReusePort(port));

  auto retryCfg = baseConfig(port, tmp);
  REQUIRE_NOTHROW(iora::IoraService::init(retryCfg));
  REQUIRE(iora::IoraService::instanceRef().webhookServer() != nullptr);
  REQUIRE_NOTHROW(iora::IoraService::shutdown());
  REQUIRE(iora::IoraService::getInstancePtr() == nullptr);
}

TEST_CASE("Failed init after a plugin loaded unloads it and a retry starts clean",
          "[iora][init][rollback]")
{
  TempDirManager tmp;
  const int port = testnet::getFreePortTCP();
  auto cfg = baseConfig(port, tmp);
  cfg.log.level = "info";
  cfg.log.async = false;
  cfg.modules.directory = iora::util::getExecutableDir() + "/plugins";
  cfg.modules.modules = std::vector<std::string>{kPluginName};

  UnloadTeardownControl ctl;
  AlwaysShutdown guard;
  auto exportCtl = [&ctl](iora::IoraService &svc)
  {
    svc.exportApi(std::string("test-harness"), "test.unloadctl",
                  [&ctl]() -> UnloadTeardownControl * { return &ctl; });
  };

  auto held = iora::IoraService::instance();
  exportCtl(*held);
  {
    ThrowOnAppliedGuard throwGuard;
    REQUIRE_THROWS_WITH(iora::IoraService::init(cfg), "injected failure after plugin load");
  }

  REQUIRE(ctl.mbOnUnloadRan.load() == 1);
  REQUIRE_FALSE(held->isModuleLoaded(kPluginName));
  REQUIRE(iora::IoraService::getInstancePtr() == nullptr);
  REQUIRE(connectRefused(port));

  auto fresh = iora::IoraService::instance();
  REQUIRE(fresh.get() != held.get());
  exportCtl(*fresh);
  REQUIRE_NOTHROW(iora::IoraService::init(cfg));
  REQUIRE(iora::IoraService::instance().get() == fresh.get());
  REQUIRE(fresh->isModuleLoaded(kPluginName));
}

TEST_CASE("Concurrent shutdown calls tear the service down once",
          "[iora][init][shutdown][concurrency]")
{
  constexpr int kIterations = 50;
  constexpr int kThreads = 8;

  TempDirManager tmp;
  iora::IoraService::Config cfg;
  cfg.features.server = false;
  cfg.features.jsonFileStore = false;
  cfg.features.stateStore = false;
  cfg.features.expiringCache = false;
  cfg.features.modules = false;
  cfg.log.file = tmp.filePath("log");
  cfg.log.level = "error";

  AlwaysShutdown guard;
  for (int iteration = 0; iteration < kIterations; ++iteration)
  {
    iora::IoraService::init(cfg);

    std::mutex barrierMutex;
    std::condition_variable barrierCv;
    bool open = false;
    int ready = 0;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    struct Joiner
    {
      std::mutex &mutex;
      std::condition_variable &cv;
      bool &open;
      std::vector<std::thread> &threads;
      ~Joiner()
      {
        {
          std::lock_guard<std::mutex> lock(mutex);
          open = true;
        }
        cv.notify_all();
        for (auto &t : threads)
        {
          if (t.joinable())
          {
            t.join();
          }
        }
      }
    };
    bool readyInTime = false;
    {
      Joiner joiner{barrierMutex, barrierCv, open, threads};
      for (int i = 0; i < kThreads; ++i)
      {
        threads.emplace_back(
          [&]
          {
            {
              std::unique_lock<std::mutex> lock(barrierMutex);
              ++ready;
              barrierCv.notify_all();
              barrierCv.wait(lock, [&] { return open; });
            }
            iora::IoraService::shutdown();
          });
      }
      std::unique_lock<std::mutex> lock(barrierMutex);
      readyInTime =
        barrierCv.wait_for(lock, std::chrono::seconds(10), [&] { return ready == kThreads; });
    }

    INFO("iteration " << iteration);
    REQUIRE(readyInTime);
    REQUIRE(iora::IoraService::getInstancePtr() == nullptr);
  }
}
