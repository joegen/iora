// File: iora/tests/service/iora_test_plugin_callback_lifecycle.cpp
//
// Plugin callback ownership through the IoraService lifecycle (tracker
// 2026-10-16-12, architecture/iora/plugin_callback_ownership.json P-1..P-14).
// Webhook routes and EventQueue handlers registered by a plugin are closed
// until its load commits, drained and removed before its dlclose, restored on a
// failed unload, never duplicated by a reload, and a callback cannot unload its
// own module. Each TEST_CASE runs on its own IoraService (init ... shutdown).
// Every pass/kill criterion is behavioral (counters, HTTP status, bounded
// waits); the probe plugins are not sanitizer-instrumented.
#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include "../plugins/callback_control.hpp"
#include "iora_test_net_utils.hpp" // uses Catch2 REQUIRE -> must follow catch.hpp

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>

using namespace std::chrono_literals;
using iora::core::CallbackGate;
using iora::test::CallbackControl;
using iora::test::CallbackSlot;
using iora::test::ProbeMode;
using iora::test::SelfUnloadOp;
using iora::test::SelfUnloadResult;

namespace
{

const std::string P = "callbackprobeplugin.so";
const std::string N = "callbackprobeplugin_b.so";
const std::string DEP = "callbackdependentplugin.so";
constexpr auto BOUND = 5s;
constexpr auto QUIET = 200ms;

CallbackControl g_ctl;

std::string pluginPath(const std::string &name)
{
  return iora::util::getExecutableDir() + "/plugins/" + name;
}

/// Releases every probe parked at phase 1.
void releaseAllProbes()
{
  for (auto &probe : g_ctl.probes)
  {
    probe.phase.store(2);
  }
}

/// One IoraService for one TEST_CASE, with its webhook server on a free port.
struct Service
{
  int port = 0;
  iora::IoraService *svc = nullptr;

  Service()
  {
    g_ctl.probes[0].reset(P);
    g_ctl.probes[1].reset(N);
    g_ctl.dependent.reset();
    port = testnet::getFreePortTCP();
    iora::IoraService::Config config;
    config.server.port = port;
    config.state.file = "ioraservice_plugin_callback_lifecycle_state.json";
    config.log.file = "ioraservice_plugin_callback_lifecycle_log";
    config.modules.autoLoad = false;
    iora::IoraService::init(config);
    svc = &iora::IoraService::instanceRef();
    svc->exportApi(std::string("test-harness"), "test.cbctl",
                   []() -> CallbackControl * { return &g_ctl; });
  }

  ~Service()
  {
    releaseAllProbes();
    try
    {
      iora::IoraService::shutdown();
    }
    catch (...)
    {
    }
  }
};

CallbackSlot &slot(const std::string &name)
{
  return *g_ctl.slotFor(name);
}

struct Reply
{
  int status = 0;
  std::string body;
};

/// One request on a fresh connection with Connection: close; reads to EOF.
Reply http(int port, const std::string &method, const std::string &path)
{
  Reply r;
  const std::string body = method == "POST" ? "{}" : "";
  const std::string raw = testnet::rawHttpRequest(
    port, method + " " + path +
            " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
            "Content-Type: application/json\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\n\r\n" + body);
  const auto sp = raw.find(' ');
  if (sp != std::string::npos && raw.size() >= sp + 4)
  {
    r.status = std::stoi(raw.substr(sp + 1, 3));
  }
  const auto split = raw.find("\r\n\r\n");
  if (split != std::string::npos)
  {
    r.body = raw.substr(split + 4);
  }
  return r;
}

bool portRefuses(int port)
{
  const int fd = testnet::connectLoopbackTcp(port, 1);
  if (fd >= 0)
  {
    ::close(fd);
  }
  return fd < 0;
}

void push(iora::IoraService &svc, const std::string &id, const std::string &name)
{
  auto e = iora::parsers::Json::object();
  e["eventId"] = id;
  e["eventName"] = name;
  svc.pushEvent(e);
}

/// True once the module's CallbackGate refuses admission (an admitted probe is
/// released at once, so polling never holds the drain).
bool waitClosed(const std::string &name)
{
  return iora::test::waitFor(
    [&]
    {
      auto a = CallbackGate::admit(name);
      return !a;
    },
    BOUND);
}

/// Runs fn on a worker thread; detached on timeout so a deadlock regression
/// fails the test instead of hanging it (the ctest TIMEOUT is the backstop).
template <typename T> struct Bounded
{
  struct State
  {
    std::atomic<bool> done{false};
    std::atomic<bool> threw{false};
    T value{};
  };
  std::shared_ptr<State> st = std::make_shared<State>();
  std::thread t;

  template <typename Fn> explicit Bounded(Fn fn)
  {
    auto s = st;
    t = std::thread(
      [s, fn]
      {
        try
        {
          s->value = fn();
        }
        catch (...)
        {
          s->threw.store(true);
        }
        s->done.store(true);
      });
  }

  bool finished(std::chrono::milliseconds budget = BOUND)
  {
    if (!t.joinable())
    {
      return st->done.load();
    }
    if (iora::test::waitFor([&] { return st->done.load(); }, budget))
    {
      t.join();
      return true;
    }
    return false;
  }

  ~Bounded()
  {
    if (t.joinable())
    {
      if (!st->done.load())
      {
        // A failing test may leave the worker parked at phase 1: release it and
        // wait (bounded) BEFORE deciding to detach, so a released worker never
        // runs on into the service teardown that follows.
        releaseAllProbes();
        iora::test::waitFor([this] { return st->done.load(); }, BOUND);
      }
      if (st->done.load())
      {
        t.join();
      }
      else
      {
        t.detach();
      }
    }
  }
};

void configureProbe(const std::string &name, ProbeMode mode, const std::string &prefix)
{
  auto &s = slot(name);
  s.mode.store(static_cast<int>(mode));
  s.eventId = prefix + ".id";
  s.eventName = prefix + ".name";
  s.eventPattern = "^" + prefix + "\\.name$";
}

std::string route(const std::string &module, const std::string &leaf)
{
  return "/" + module + "/" + leaf;
}

} // namespace

TEST_CASE("P-1 an event handler in flight holds unloadSingleModule; window is closed")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::SLOW, "p");
  REQUIRE(svc.loadSingleModule(pluginPath(P)));

  push(svc, "p.id", "p.name");
  REQUIRE(iora::test::waitFor([&] { return slot(P).phase.load() == 1; }, BOUND));

  Bounded<bool> unload([&svc] { return svc.unloadSingleModule(P); });
  std::this_thread::sleep_for(150ms);
  REQUIRE_FALSE(unload.st->done.load());

  REQUIRE(waitClosed(P));
  const int before = slot(P).invocations.load();
  REQUIRE(http(s.port, "POST", route(P, "post")).status == 503);
  push(svc, "p.id", "p.other");
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == before);

  slot(P).phase.store(2);
  REQUIRE(unload.finished());
  REQUIRE(unload.st->value);
  REQUIRE_FALSE(slot(P).unloadRanBeforeRead.load());
  REQUIRE(slot(P).observedMagic.load() == 0xC0FFEE);

  const int after = slot(P).invocations.load();
  for (int i = 0; i < 5; ++i)
  {
    push(svc, "p.id", "p.name");
  }
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == after);
}

TEST_CASE("P-2 a webhook route in flight holds unloadSingleModule; route gone after")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::SLOW, "p");
  REQUIRE(svc.loadSingleModule(pluginPath(P)));

  const int port = s.port;
  Bounded<int> post([port] { return http(port, "POST", route(P, "post")).status; });
  REQUIRE(iora::test::waitFor([&] { return slot(P).phase.load() == 1; }, BOUND));

  Bounded<bool> unload([&svc] { return svc.unloadSingleModule(P); });
  std::this_thread::sleep_for(150ms);
  REQUIRE_FALSE(unload.st->done.load());

  REQUIRE(waitClosed(P));
  const int before = slot(P).invocations.load();
  REQUIRE(http(s.port, "POST", route(P, "post")).status == 503);
  push(svc, "p.id", "p.other");
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == before);

  slot(P).phase.store(2);
  REQUIRE(unload.finished());
  REQUIRE(unload.st->value);
  REQUIRE(post.finished());
  REQUIRE(post.st->value == 200);
  REQUIRE_FALSE(slot(P).unloadRanBeforeRead.load());
  REQUIRE(slot(P).observedMagic.load() == 0xC0FFEE);
  REQUIRE(http(s.port, "POST", route(P, "post")).status == 404);
}

TEST_CASE("P-3 reloadModule leaves exactly one handler and one route")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::NORMAL, "p");
  REQUIRE(svc.loadSingleModule(pluginPath(P)));
  REQUIRE(svc.reloadModule(P));

  push(svc, "p.id", "p.other");
  REQUIRE(iora::test::waitFor([&] { return slot(P).invocations.load() >= 1; }, BOUND));
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == 1);

  REQUIRE(http(s.port, "GET", route(P, "named/7")).status == 200);
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == 2);
}

TEST_CASE("P-4 a failed load leaves no handler and no route")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::THROW_AFTER_REGISTER, "p");
  bool loaded = true;
  try
  {
    loaded = svc.loadSingleModule(pluginPath(P));
  }
  catch (const std::exception &)
  {
    loaded = false;
  }
  REQUIRE_FALSE(loaded);
  REQUIRE_FALSE(svc.isModuleLoaded(P));

  push(svc, "p.id", "p.name");
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == 0);
  REQUIRE(http(s.port, "GET", route(P, "get")).status == 404);
  REQUIRE(http(s.port, "POST", route(P, "post")).status == 404);
}

TEST_CASE("P-5 callbacks are closed until the load commits")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::BLOCK_IN_ONLOAD, "p");
  Bounded<bool> load([&svc] { return svc.loadSingleModule(pluginPath(P)); });
  REQUIRE(iora::test::waitFor([&] { return slot(P).phase.load() == 1; }, BOUND));

  REQUIRE(http(s.port, "POST", route(P, "post")).status == 503);
  push(svc, "p.id", "p.other");
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == 0);

  slot(P).phase.store(2);
  REQUIRE(load.finished());
  REQUIRE(load.st->value);
  REQUIRE(http(s.port, "POST", route(P, "post")).status == 200);
  push(svc, "p.id", "p.other");
  REQUIRE(iora::test::waitFor([&] { return slot(P).invocations.load() == 2; }, BOUND));
}

TEST_CASE("P-6 a callback cannot unload its own module")
{
  Service s;
  auto &svc = *s.svc;

  SECTION("unloadSingleModule from the handler throws; the host can unload later")
  {
    configureProbe(P, ProbeMode::SELF_UNLOAD, "p");
    slot(P).selfUnloadOp.store(static_cast<int>(SelfUnloadOp::UNLOAD));
    REQUIRE(svc.loadSingleModule(pluginPath(P)));
    push(svc, "p.id", "p.other");
    REQUIRE(iora::test::waitFor([&] { return slot(P).selfUnloadDone.load(); }, BOUND));
    REQUIRE(slot(P).selfUnloadResult.load() == static_cast<int>(SelfUnloadResult::THREW));
    REQUIRE(svc.isModuleLoaded(P));
    REQUIRE(svc.unloadSingleModule(P));
  }

  SECTION("reloadModule from the handler throws")
  {
    configureProbe(P, ProbeMode::SELF_UNLOAD, "p");
    slot(P).selfUnloadOp.store(static_cast<int>(SelfUnloadOp::RELOAD));
    REQUIRE(svc.loadSingleModule(pluginPath(P)));
    push(svc, "p.id", "p.other");
    REQUIRE(iora::test::waitFor([&] { return slot(P).selfUnloadDone.load(); }, BOUND));
    REQUIRE(slot(P).selfUnloadResult.load() == static_cast<int>(SelfUnloadResult::THREW));
    REQUIRE(svc.isModuleLoaded(P));
    REQUIRE(svc.unloadSingleModule(P));
  }

  SECTION("unloadAllModules from the handler skips it and unloads the others")
  {
    configureProbe(P, ProbeMode::SELF_UNLOAD, "p");
    slot(P).selfUnloadOp.store(static_cast<int>(SelfUnloadOp::UNLOAD_ALL));
    configureProbe(N, ProbeMode::NORMAL, "n");
    REQUIRE(svc.loadSingleModule(pluginPath(P)));
    REQUIRE(svc.loadSingleModule(pluginPath(N)));
    push(svc, "p.id", "p.other");
    REQUIRE(iora::test::waitFor([&] { return slot(P).selfUnloadDone.load(); }, BOUND));
    REQUIRE(slot(P).selfUnloadResult.load() ==
            static_cast<int>(SelfUnloadResult::RETURNED_FALSE));
    REQUIRE(svc.isModuleLoaded(P));
    REQUIRE_FALSE(svc.isModuleLoaded(N));
    REQUIRE(svc.unloadSingleModule(P));
  }
}

TEST_CASE("P-7 a failed unload restores the callbacks; a second unload removes them")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::THROW_IN_ONUNLOAD_ONCE, "p");
  slot(P).throwOnce.store(true);
  REQUIRE(svc.loadSingleModule(pluginPath(P)));

  bool first = true;
  try
  {
    first = svc.unloadSingleModule(P);
  }
  catch (const std::exception &)
  {
    first = false;
  }
  REQUIRE_FALSE(first);
  REQUIRE(svc.isModuleLoaded(P));

  push(svc, "p.id", "p.other");
  REQUIRE(iora::test::waitFor([&] { return slot(P).invocations.load() == 1; }, BOUND));
  REQUIRE(http(s.port, "GET", route(P, "get")).status == 200);

  REQUIRE(svc.unloadSingleModule(P));
  const int after = slot(P).invocations.load();
  push(svc, "p.id", "p.other");
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == after);
  REQUIRE(http(s.port, "GET", route(P, "get")).status == 404);
}

TEST_CASE("P-8 a handler registered inside onUnload never runs and is removed")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::REGISTER_IN_ONUNLOAD, "p");
  REQUIRE(svc.loadSingleModule(pluginPath(P)));
  REQUIRE(svc.unloadSingleModule(P));
  push(svc, "p.late", "p.name.late");
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).lateInvocations.load() == 0);
}

TEST_CASE("P-9 registrations are attributed to the plugin whose hook made them")
{
  std::atomic<int> host{0};
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::NORMAL, "p");
  svc.eventQueue().onEventName("host.evt", [&host](const iora::parsers::Json &) { ++host; });
  REQUIRE(svc.loadSingleModule(pluginPath(P)));
  REQUIRE(svc.loadSingleModule(pluginPath(DEP)));
  REQUIRE(svc.unloadSingleModule(P));

  auto &dep = g_ctl.dependent;
  push(svc, "d1", "dep.onload");
  push(svc, "d2", "dep.loaded");
  push(svc, "d3", "dep.unloaded");
  push(svc, "h1", "host.evt");
  REQUIRE(iora::test::waitFor(
    [&]
    {
      return dep.onLoadHandler.load() == 1 && dep.depLoadedHandler.load() == 1 &&
             dep.depUnloadedHandler.load() == 1 && host.load() == 1;
    },
    BOUND));

  // Reload the dependency while DEP stays loaded: notifyDependentsOfLoad runs
  // DEP's onDependencyLoaded while the probe's own load scope is still open, so
  // the handler it registers must still belong to DEP (not to the probe).
  REQUIRE(svc.loadSingleModule(pluginPath(P)));
  push(svc, "d4", "dep.reloaded");
  REQUIRE(iora::test::waitFor([&] { return dep.depReloadedHandler.load() == 1; }, BOUND));
  REQUIRE(svc.unloadSingleModule(P));
  push(svc, "d4", "dep.reloaded");
  REQUIRE(iora::test::waitFor([&] { return dep.depReloadedHandler.load() == 2; }, BOUND));

  REQUIRE(svc.unloadSingleModule(DEP));
  push(svc, "d1", "dep.onload");
  push(svc, "d2", "dep.loaded");
  push(svc, "d3", "dep.unloaded");
  push(svc, "d4", "dep.reloaded");
  push(svc, "h1", "host.evt");
  REQUIRE(iora::test::waitFor([&] { return host.load() == 2; }, BOUND));
  std::this_thread::sleep_for(QUIET);
  REQUIRE(dep.onLoadHandler.load() == 1);
  REQUIRE(dep.depLoadedHandler.load() == 1);
  REQUIRE(dep.depUnloadedHandler.load() == 1);
  REQUIRE(dep.depReloadedHandler.load() == 2);
}

TEST_CASE("P-10 shutdown waits for an event handler in flight; window is closed")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::SLOW, "p");
  REQUIRE(svc.loadSingleModule(pluginPath(P)));
  push(svc, "p.id", "p.other");
  REQUIRE(iora::test::waitFor([&] { return slot(P).phase.load() == 1; }, BOUND));

  Bounded<bool> stop(
    []
    {
      iora::IoraService::shutdown();
      return true;
    });
  REQUIRE(waitClosed(P));
  REQUIRE_FALSE(stop.st->done.load());
  const int before = slot(P).invocations.load();
  push(svc, "p.id", "p.other");
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == before);

  slot(P).phase.store(2);
  REQUIRE(stop.finished());
  REQUIRE_FALSE(slot(P).unloadRanBeforeRead.load());
  REQUIRE(slot(P).observedMagic.load() == 0xC0FFEE);
  REQUIRE(slot(P).unloadRan.load());
}

TEST_CASE("P-11 unloadAllModules drains two modules in flight; both windows closed")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::SLOW, "p");
  configureProbe(N, ProbeMode::SLOW, "n");
  REQUIRE(svc.loadSingleModule(pluginPath(P)));
  REQUIRE(svc.loadSingleModule(pluginPath(N)));
  push(svc, "p.id", "p.other");
  push(svc, "n.id", "n.other");
  REQUIRE(iora::test::waitFor(
    [&] { return slot(P).phase.load() == 1 && slot(N).phase.load() == 1; }, BOUND));

  Bounded<bool> unloadAll([&svc] { return svc.unloadAllModules(); });
  REQUIRE(waitClosed(P));
  REQUIRE(waitClosed(N));
  REQUIRE_FALSE(unloadAll.st->done.load());
  const int beforeP = slot(P).invocations.load();
  const int beforeN = slot(N).invocations.load();
  REQUIRE(http(s.port, "POST", route(P, "post")).status == 503);
  REQUIRE(http(s.port, "POST", route(N, "post")).status == 503);
  push(svc, "p.id", "p.other");
  push(svc, "n.id", "n.other");
  std::this_thread::sleep_for(QUIET);
  REQUIRE(slot(P).invocations.load() == beforeP);
  REQUIRE(slot(N).invocations.load() == beforeN);

  slot(P).phase.store(2);
  slot(N).phase.store(2);
  REQUIRE(unloadAll.finished());
  REQUIRE(unloadAll.st->value);
  REQUIRE_FALSE(svc.isModuleLoaded(P));
  REQUIRE_FALSE(svc.isModuleLoaded(N));
  REQUIRE_FALSE(slot(P).unloadRanBeforeRead.load());
  REQUIRE_FALSE(slot(N).unloadRanBeforeRead.load());
}

TEST_CASE("P-13 shutdown overlapping unloadSingleModule resets the server under the lock")
{
  Service s;
  auto &svc = *s.svc;
  configureProbe(P, ProbeMode::BLOCK_IN_ONUNLOAD, "p");
  configureProbe(N, ProbeMode::BLOCK_IN_ONUNLOAD, "n");
  REQUIRE(svc.loadSingleModule(pluginPath(P)));
  REQUIRE(svc.loadSingleModule(pluginPath(N)));
  REQUIRE(http(s.port, "GET", route(P, "get")).status == 200);

  Bounded<bool> unload([&svc] { return svc.unloadSingleModule(P); });
  REQUIRE(iora::test::waitFor([&] { return slot(P).phase.load() == 1; }, BOUND));

  Bounded<bool> stop(
    []
    {
      iora::IoraService::shutdown();
      return true;
    });
  const int port = s.port;
  REQUIRE(iora::test::waitFor([port] { return portRefuses(port); }, BOUND));

  slot(P).phase.store(2);
  REQUIRE(unload.finished());
  REQUIRE(unload.st->value);
  REQUIRE(iora::test::waitFor([&] { return slot(N).phase.load() == 1; }, BOUND));
  slot(N).phase.store(2);
  REQUIRE(stop.finished());
}

TEST_CASE("P-14 an unload from a co-dispatched handler")
{
  Service s;
  auto &svc = *s.svc;

  SECTION("a host handler that runs before the probe's handler is refused")
  {
    configureProbe(P, ProbeMode::NORMAL, "p");
    slot(P).eventId.clear();
    slot(P).eventName.clear();
    slot(P).eventPattern = "^admin\\.unload$";
    auto result = std::make_shared<std::atomic<int>>(0);
    svc.eventQueue().onEventName("admin.unload",
                                 [&svc, result](const iora::parsers::Json &)
                                 {
                                   try
                                   {
                                     result->store(svc.unloadSingleModule(P) ? 2 : 3);
                                   }
                                   catch (const std::runtime_error &)
                                   {
                                     result->store(1);
                                   }
                                 });
    REQUIRE(svc.loadSingleModule(pluginPath(P)));
    push(svc, "a.id", "admin.unload");
    REQUIRE(iora::test::waitFor([&] { return result->load() != 0; }, BOUND));
    REQUIRE(result->load() == 1);
    REQUIRE(iora::test::waitFor([&] { return slot(P).invocations.load() == 1; }, BOUND));
    REQUIRE(svc.unloadSingleModule(P));
  }

  SECTION("a host handler that runs after the probe's handler succeeds")
  {
    configureProbe(P, ProbeMode::NORMAL, "p");
    slot(P).eventId = "p14.id";
    slot(P).eventName.clear();
    slot(P).eventPattern.clear();
    auto result = std::make_shared<std::atomic<int>>(0);
    svc.eventQueue().onEventName("admin.unload2",
                                 [&svc, result](const iora::parsers::Json &)
                                 {
                                   try
                                   {
                                     result->store(svc.unloadSingleModule(P) ? 2 : 3);
                                   }
                                   catch (const std::runtime_error &)
                                   {
                                     result->store(1);
                                   }
                                 });
    REQUIRE(svc.loadSingleModule(pluginPath(P)));
    push(svc, "p14.id", "admin.unload2");
    REQUIRE(iora::test::waitFor([&] { return result->load() != 0; }, BOUND));
    REQUIRE(result->load() == 2);
    REQUIRE(slot(P).invocations.load() == 1);
    REQUIRE_FALSE(svc.isModuleLoaded(P));
  }
}

int main(int argc, char *argv[])
{
  Catch::Session session;
  testnet::ignoreSigpipeForTestProcess();
  iora::test::initializeTestLogging();
  const int result = session.run(argc, argv);
  iora::util::removeFilesContainingAny({"ioraservice_plugin_callback_lifecycle_log",
                                        "ioraservice_plugin_callback_lifecycle_state.json"});
  return result;
}
