// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for CallbackOwner and CallbackGate (plugin_callback_ownership C1).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/callback_ownership.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <utility>

using iora::core::CallbackGate;
using iora::core::CallbackOwner;

namespace
{

constexpr auto BOUND = std::chrono::seconds(5);
constexpr auto SETTLE = std::chrono::milliseconds(100);

/// Runs drain(owner) on a detached thread so a hang fails the test instead of
/// wedging it.
std::shared_future<void> drainAsync(const std::string &owner)
{
  auto done = std::make_shared<std::promise<void>>();
  std::shared_future<void> f = done->get_future().share();
  std::thread(
    [done, owner]
    {
      CallbackGate::drain(owner);
      done->set_value();
    })
    .detach();
  return f;
}

bool returnsWithin(const std::shared_future<void> &f, std::chrono::milliseconds d)
{
  return f.wait_for(d) == std::future_status::ready;
}

/// Holds an admission of owner on its own thread until release() is called.
class RemoteHolder
{
public:
  explicit RemoteHolder(std::string owner) : _owner(std::move(owner))
  {
    _thread = std::thread(
      [this]
      {
        {
          auto a = CallbackGate::admit(_owner);
          _admitted = static_cast<bool>(a);
          _ready.set_value();
          _go.get_future().wait();
        }
        _released.set_value();
      });
    _ready.get_future().wait();
  }

  ~RemoteHolder()
  {
    release();
    _thread.join();
  }

  void release()
  {
    if (!_releasedOnce)
    {
      _releasedOnce = true;
      _go.set_value();
      _released.get_future().wait();
    }
  }

  bool admitted() const { return _admitted; }

private:
  std::string _owner;
  bool _admitted = false;
  bool _releasedOnce = false;
  std::promise<void> _ready;
  std::promise<void> _go;
  std::promise<void> _released;
  std::thread _thread;
};

} // namespace

TEST_CASE("U-1 Scope sets current() and nested scopes restore in order", "[callback_ownership]")
{
  REQUIRE(CallbackOwner::current().empty());
  {
    CallbackOwner::Scope a("A");
    REQUIRE(CallbackOwner::current() == "A");
    {
      CallbackOwner::Scope b("B");
      REQUIRE(CallbackOwner::current() == "B");
      {
        CallbackOwner::Scope none("");
        REQUIRE(CallbackOwner::current().empty());
      }
      REQUIRE(CallbackOwner::current() == "B");
    }
    REQUIRE(CallbackOwner::current() == "A");
  }
  REQUIRE(CallbackOwner::current().empty());

  std::string other;
  CallbackOwner::Scope a("A");
  std::thread(
    [&other]
    {
      other = CallbackOwner::current();
    })
    .join();
  REQUIRE(other.empty());
}

TEST_CASE("U-2 admit of an empty owner is admitted and counts nothing", "[callback_ownership]")
{
  auto a = CallbackGate::admit("");
  REQUIRE(static_cast<bool>(a));
  REQUIRE_FALSE(CallbackGate::admittedOnThisThread(""));
  auto f = drainAsync("");
  REQUIRE(returnsWithin(f, BOUND));
}

TEST_CASE("U-3 admit counts, moves transfer, move-assign releases", "[callback_ownership]")
{
  const std::string A = "u3.A";
  const std::string B = "u3.B";

  SECTION("admittedOnThisThread is true until the admission is destroyed")
  {
    {
      auto a = CallbackGate::admit(A);
      REQUIRE(static_cast<bool>(a));
      REQUIRE(CallbackGate::admittedOnThisThread(A));
    }
    REQUIRE_FALSE(CallbackGate::admittedOnThisThread(A));
  }

  SECTION("a moved-from admission releases nothing")
  {
    auto a = CallbackGate::admit(A);
    {
      CallbackGate::Admission moved(std::move(a));
      REQUIRE(static_cast<bool>(moved));
      REQUIRE_FALSE(static_cast<bool>(a));
      REQUIRE(CallbackGate::admittedOnThisThread(A));
    }
    REQUIRE_FALSE(CallbackGate::admittedOnThisThread(A));
    {
      CallbackGate::Admission dead(std::move(a));
      REQUIRE_FALSE(static_cast<bool>(dead));
    }
    REQUIRE_FALSE(CallbackGate::admittedOnThisThread(A));
  }

  SECTION("two admissions need two releases")
  {
    auto first = std::make_unique<CallbackGate::Admission>(CallbackGate::admit(A));
    auto second = std::make_unique<CallbackGate::Admission>(CallbackGate::admit(A));
    first.reset();
    REQUIRE(CallbackGate::admittedOnThisThread(A));
    auto f = drainAsync(A);
    REQUIRE_FALSE(returnsWithin(f, SETTLE));
    second.reset();
    REQUIRE_FALSE(CallbackGate::admittedOnThisThread(A));
    REQUIRE(returnsWithin(f, BOUND));
  }

  SECTION("assigning an empty admission over a counted one releases it at once")
  {
    auto a = CallbackGate::admit(A);
    auto f = drainAsync(A);
    REQUIRE_FALSE(returnsWithin(f, SETTLE));
    a = CallbackGate::Admission{};
    REQUIRE_FALSE(CallbackGate::admittedOnThisThread(A));
    REQUIRE(returnsWithin(f, BOUND));
    REQUIRE_FALSE(static_cast<bool>(a));
  }

  SECTION("assigning B over A releases A and keeps B")
  {
    auto a = CallbackGate::admit(A);
    auto b = CallbackGate::admit(B);
    a = std::move(b);
    REQUIRE(static_cast<bool>(a));
    REQUIRE_FALSE(static_cast<bool>(b));
    REQUIRE_FALSE(CallbackGate::admittedOnThisThread(A));
    REQUIRE(CallbackGate::admittedOnThisThread(B));
    auto fa = drainAsync(A);
    REQUIRE(returnsWithin(fa, BOUND));
    auto fb = drainAsync(B);
    REQUIRE_FALSE(returnsWithin(fb, SETTLE));
    a = CallbackGate::Admission{};
    REQUIRE(returnsWithin(fb, BOUND));
  }

  SECTION("self-move-assignment releases nothing")
  {
    auto a = CallbackGate::admit(A);
    auto &self = a;
    a = std::move(self);
    REQUIRE(static_cast<bool>(a));
    REQUIRE(CallbackGate::admittedOnThisThread(A));
  }

  REQUIRE_FALSE(CallbackGate::admittedOnThisThread(A));
  REQUIRE_FALSE(CallbackGate::admittedOnThisThread(B));
}

TEST_CASE("U-4 close blocks admit, open restores it", "[callback_ownership]")
{
  const std::string A = "u4.A";
  CallbackGate::close(A);
  {
    auto a = CallbackGate::admit(A);
    REQUIRE_FALSE(static_cast<bool>(a));
    REQUIRE_FALSE(CallbackGate::admittedOnThisThread(A));
  }
  CallbackGate::open(A);
  {
    auto a = CallbackGate::admit(A);
    REQUIRE(static_cast<bool>(a));
  }
  CallbackGate::open("u4.unknown");
  auto u = CallbackGate::admit("u4.unknown");
  REQUIRE(static_cast<bool>(u));
}

TEST_CASE("U-5 drain waits for an admission on another thread", "[callback_ownership]")
{
  const auto run = [](const std::string &owner, bool closeFirst)
  {
    RemoteHolder holder(owner);
    REQUIRE(holder.admitted());
    if (closeFirst)
    {
      CallbackGate::close(owner);
    }
    auto f = drainAsync(owner);
    REQUIRE_FALSE(returnsWithin(f, SETTLE));
    holder.release();
    REQUIRE(returnsWithin(f, BOUND));
    if (closeFirst)
    {
      CallbackGate::open(owner);
    }
  };

  SECTION("owner open") { run("u5.open", false); }
  SECTION("owner closed") { run("u5.closed", true); }
}

TEST_CASE("U-6 drain returns at once when idle and ignores other owners", "[callback_ownership]")
{
  auto idle = drainAsync("u6.A");
  REQUIRE(returnsWithin(idle, BOUND));

  RemoteHolder holder("u6.B");
  REQUIRE(holder.admitted());
  auto f = drainAsync("u6.A");
  REQUIRE(returnsWithin(f, BOUND));
}

TEST_CASE("U-7 an empty owner is never gated", "[callback_ownership]")
{
  CallbackGate::close("");
  auto f = drainAsync("");
  REQUIRE(returnsWithin(f, BOUND));
  CallbackGate::open("");
  CallbackGate::close("");
  auto a = CallbackGate::admit("");
  REQUIRE(static_cast<bool>(a));
}

TEST_CASE("U-8 repeated cycles leave the owner clean", "[callback_ownership]")
{
  const std::string A = "u8.A";
  for (int i = 0; i < 50; ++i)
  {
    {
      auto a = CallbackGate::admit(A);
      REQUIRE(static_cast<bool>(a));
    }
    CallbackGate::close(A);
    {
      auto refused = CallbackGate::admit(A);
      REQUIRE_FALSE(static_cast<bool>(refused));
    }
    CallbackGate::open(A);
  }
  auto a = CallbackGate::admit(A);
  REQUIRE(static_cast<bool>(a));
  a = CallbackGate::Admission{};
  REQUIRE_FALSE(CallbackGate::admittedOnThisThread(A));
  auto f = drainAsync(A);
  REQUIRE(returnsWithin(f, BOUND));
}
