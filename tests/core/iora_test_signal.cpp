// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for Signal<Args...>

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/signal.hpp>

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace iora::core;

// ══════════════════════════════════════════════════════════════════════════════
// Basic Connect + Emit
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Signal: basic connect and emit", "[signal]")
{
  Signal<int, std::string> sig;
  int received = 0;
  std::string msg;

  sig.connect([&](const int& i, const std::string& s)
  {
    received = i;
    msg = s;
  });

  sig.emit(42, "hello");
  REQUIRE(received == 42);
  REQUIRE(msg == "hello");
}

TEST_CASE("Signal<>: zero-arg signal", "[signal]")
{
  Signal<> sig;
  int count = 0;
  sig.connect([&]() { ++count; });
  sig.emit();
  REQUIRE(count == 1);
  sig.emit();
  REQUIRE(count == 2);
}

TEST_CASE("Signal: multiple subscribers", "[signal]")
{
  Signal<int> sig;
  std::vector<int> log;

  sig.connect([&](const int& v) { log.push_back(v * 1); });
  sig.connect([&](const int& v) { log.push_back(v * 2); });
  sig.connect([&](const int& v) { log.push_back(v * 3); });

  sig.emit(10);
  REQUIRE(log.size() == 3);
  REQUIRE(log[0] == 10);
  REQUIRE(log[1] == 20);
  REQUIRE(log[2] == 30);
}

// ══════════════════════════════════════════════════════════════════════════════
// Disconnect
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Signal: disconnect by id", "[signal]")
{
  Signal<> sig;
  int a = 0, b = 0, c = 0;

  sig.connect([&]() { ++a; });
  auto idB = sig.connect([&]() { ++b; });
  sig.connect([&]() { ++c; });

  sig.disconnect(idB);
  sig.emit();
  REQUIRE(a == 1);
  REQUIRE(b == 0);
  REQUIRE(c == 1);
}

TEST_CASE("Signal: disconnectAll", "[signal]")
{
  Signal<> sig;
  int count = 0;
  sig.connect([&]() { ++count; });
  sig.connect([&]() { ++count; });
  sig.disconnectAll();
  sig.emit();
  REQUIRE(count == 0);
}

// ══════════════════════════════════════════════════════════════════════════════
// connectionCount / empty
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Signal: connectionCount and empty", "[signal]")
{
  Signal<> sig;
  REQUIRE(sig.empty());
  REQUIRE(sig.connectionCount() == 0);

  auto id1 = sig.connect([&]() {});
  REQUIRE(sig.connectionCount() == 1);
  REQUIRE_FALSE(sig.empty());

  sig.connect([&]() {});
  REQUIRE(sig.connectionCount() == 2);

  sig.disconnect(id1);
  REQUIRE(sig.connectionCount() == 1);

  sig.disconnectAll();
  REQUIRE(sig.empty());
}

TEST_CASE("Signal: connectionCount includes expired-but-unpruned weak_ptr", "[signal]")
{
  Signal<> sig;

  struct Listener
  {
    void onEvent() {}
  };

  auto sp = std::make_shared<Listener>();
  sig.connect(std::weak_ptr<Listener>(sp), &Listener::onEvent);
  REQUIRE(sig.connectionCount() == 1);

  sp.reset(); // expire the weak_ptr
  // Before emit (which triggers prune), count still includes expired slot
  REQUIRE(sig.connectionCount() == 1);

  sig.emit(); // triggers prune
  REQUIRE(sig.connectionCount() == 0);
}

// ══════════════════════════════════════════════════════════════════════════════
// weak_ptr Auto-Disconnect
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Signal: weak_ptr auto-disconnect on expiry", "[signal][weak]")
{
  Signal<> sig;

  struct Listener
  {
    int count = 0;
    void onEvent() { ++count; }
  };

  auto sp = std::make_shared<Listener>();
  sig.connect(std::weak_ptr<Listener>(sp), &Listener::onEvent);

  sig.emit();
  REQUIRE(sp->count == 1);

  sp.reset(); // expire
  sig.emit(); // slot skipped + pruned
  // No crash, and the slot was pruned
  REQUIRE(sig.connectionCount() == 0);
}

// ══════════════════════════════════════════════════════════════════════════════
// ScopedConnection
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Signal: ScopedConnection auto-disconnect", "[signal][scoped]")
{
  Signal<> sig;
  int count = 0;

  {
    auto id = sig.connect([&]() { ++count; });
    Signal<>::ScopedConnection sc(&sig, id);
    sig.emit();
    REQUIRE(count == 1);
  } // sc destroyed → disconnect

  sig.emit();
  REQUIRE(count == 1); // not called again
}

TEST_CASE("Signal: ScopedConnection move semantics", "[signal][scoped]")
{
  Signal<> sig;
  int count = 0;
  auto id = sig.connect([&]() { ++count; });

  Signal<>::ScopedConnection sc1(&sig, id);
  Signal<>::ScopedConnection sc2(std::move(sc1));
  // sc1 is now no-op

  sig.emit();
  REQUIRE(count == 1);

  sc2 = Signal<>::ScopedConnection{}; // move-assign empty → disconnects
  sig.emit();
  REQUIRE(count == 1); // slot disconnected
}

TEST_CASE("Signal: ScopedConnection release()", "[signal][scoped]")
{
  Signal<> sig;
  int count = 0;
  auto id = sig.connect([&]() { ++count; });

  {
    Signal<>::ScopedConnection sc(&sig, id);
    auto releasedId = sc.release();
    REQUIRE(releasedId == id);
  } // sc destroyed — but release() was called, so no disconnect

  sig.emit();
  REQUIRE(count == 1); // still connected
  sig.disconnect(id); // manual cleanup
}

TEST_CASE("Signal: ScopedConnection reset()", "[signal][scoped]")
{
  Signal<> sig;
  int count = 0;
  auto id = sig.connect([&]() { ++count; });

  Signal<>::ScopedConnection sc(&sig, id);
  sc.reset(); // disconnects now

  sig.emit();
  REQUIRE(count == 0);

  // Subsequent destruction is no-op (already reset)
}

TEST_CASE("Signal: ScopedConnection default constructor is no-op", "[signal][scoped]")
{
  Signal<>::ScopedConnection sc; // default
  // Destruction should not crash
}

// ══════════════════════════════════════════════════════════════════════════════
// Emit During Connect/Disconnect (COW Isolation)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Signal: slot connects another slot during emit — no deadlock", "[signal][cow]")
{
  Signal<> sig;
  int innerCount = 0;

  sig.connect([&]()
  {
    // Connect from within emit — mutex not held, COW snapshot isolates
    sig.connect([&]() { ++innerCount; });
  });

  sig.emit(); // first emit: outer fires, inner connects
  REQUIRE(innerCount == 0); // inner not in the snapshot

  sig.emit(); // second emit: both fire
  REQUIRE(innerCount == 1);
}

TEST_CASE("Signal: slot disconnects itself during emit — no deadlock", "[signal][cow]")
{
  Signal<> sig;
  ConnectionId selfId = 0;
  int count = 0;

  selfId = sig.connect([&]()
  {
    ++count;
    sig.disconnect(selfId);
  });

  sig.emit();
  REQUIRE(count == 1);

  sig.emit();
  REQUIRE(count == 1); // disconnected, not called again
}

// ══════════════════════════════════════════════════════════════════════════════
// Exception Handler
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Signal: exception handler receives exception_ptr", "[signal][exception]")
{
  Signal<> sig;
  bool handlerCalled = false;
  int normalCount = 0;

  sig.connect([&]() { throw std::runtime_error("boom"); });
  sig.connect([&]() { ++normalCount; });

  sig.setExceptionHandler([&](std::exception_ptr)
  {
    handlerCalled = true;
  });

  sig.emit();
  REQUIRE(handlerCalled);
  REQUIRE(normalCount == 1); // normal slot still fires
}

TEST_CASE("Signal: default exception swallow", "[signal][exception]")
{
  Signal<> sig;
  int normalCount = 0;

  sig.connect([&]() { throw std::runtime_error("boom"); });
  sig.connect([&]() { ++normalCount; });

  // No handler set — exceptions silently swallowed
  sig.emit();
  REQUIRE(normalCount == 1);
}

// ══════════════════════════════════════════════════════════════════════════════
// Thread Safety Stress
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Signal: concurrent stress — emit + connect/disconnect", "[signal][stress]")
{
  Signal<int> sig;
  std::atomic<int> emitCount{0};
  constexpr int iterations = 10000;

  // Emitter threads
  std::vector<std::thread> threads;
  for (int t = 0; t < 4; ++t)
  {
    threads.emplace_back([&]()
    {
      for (int i = 0; i < iterations; ++i)
      {
        sig.emit(i);
        emitCount.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }

  // Connect/disconnect threads
  for (int t = 0; t < 4; ++t)
  {
    threads.emplace_back([&]()
    {
      for (int i = 0; i < iterations; ++i)
      {
        auto id = sig.connect([](const int&) {});
        sig.disconnect(id);
      }
    });
  }

  for (auto& t : threads) t.join();

  REQUIRE(emitCount.load() == 4 * iterations);
}
