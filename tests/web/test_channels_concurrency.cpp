// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Concurrency (TSAN) tests for iora SSE/channel pub/sub.
// Tracker: 2026-05-29-7 (htmx-support phase 6); architecture: sse_and_channels.json.
//
// Run under a SEPARATE -fsanitize=thread build (iora has no built-in TSAN target):
//   cmake -S . -B build-tsan -DIORA_BUILD_WEB_TESTS=ON -DCMAKE_CXX_FLAGS="-fsanitize=thread -g -O1"
//   cmake --build build-tsan --target test_channels_concurrency
//   LD_LIBRARY_PATH=build-tsan/src/core setarch "$(uname -m)" -R ./build-tsan/tests/test_channels_concurrency
//
// Catch2 REQUIRE is NOT thread-safe (v2.13.10): worker threads record to
// std::atomic and the test asserts on the main thread after join().

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <iora/network/sse_stream.hpp>
#include <iora/web/channel.hpp>

using iora::network::SseManager;
using iora::network::SseStream;
using iora::network::SessionId;
using iora::web::SseChannel;
using iora::web::WsChannel;

namespace
{

// Thread-safe SSE server double: counts writes and records per-sid byte streams.
class ConcSseServer : public iora::network::HttpServer
{
public:
  using HttpServer::HttpServer;
  std::atomic<long> writes{0};
  std::atomic<long> closes{0};

  bool sendRawForSse(SessionId sid, const std::uint8_t *data, std::size_t len) override
  {
    writes.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(_m);
    _bytes[sid].append(reinterpret_cast<const char *>(data), len);
    return true;
  }
  void closeSession(SessionId) override { closes.fetch_add(1, std::memory_order_relaxed); }

  std::string bytesFor(SessionId sid)
  {
    std::lock_guard<std::mutex> lock(_m);
    return _bytes[sid];
  }

private:
  std::mutex _m;
  std::unordered_map<SessionId, std::string> _bytes;
};

// Thread-safe WsChannel server double. NOTE: this overrides isSessionActive /
// sendText, so it exercises WsChannel's snapshot/skip/prune logic and the
// SessionId-set race — NOT the REAL WebSocketServer _wsMutex->_mutex send-boundary
// path. The real closeSent recheck under _wsMutex (web-M7, the RFC 6455 §5.5.1
// data-after-close guarantee) is exercised against a live WebSocketServer in
// tests/web/test_application_integration.cpp.
class ConcWsServer : public iora::network::WebSocketServer
{
public:
  using WebSocketServer::WebSocketServer;

  bool isSessionActive(SessionId sid) const override
  {
    std::lock_guard<std::mutex> lock(_m);
    return _active.count(sid) != 0;
  }
  void sendText(SessionId sid, const std::string &) override
  {
    (void)sid;
    _sends.fetch_add(1, std::memory_order_relaxed);
  }
  void setActive(SessionId sid, bool on)
  {
    std::lock_guard<std::mutex> lock(_m);
    if (on)
    {
      _active.insert(sid);
    }
    else
    {
      _active.erase(sid);
    }
  }
  std::atomic<long> _sends{0};

private:
  mutable std::mutex _m;
  std::unordered_set<SessionId> _active;
};

} // namespace

TEST_CASE("conc: SseChannel concurrent publishers + subscribe/prune", "[tsan][sse]")
{
  ConcSseServer srv;
  SseChannel ch("c");
  for (SessionId i = 1; i <= 8; ++i)
  {
    ch.subscribe(std::make_shared<SseStream>(srv, i));
  }

  std::atomic<bool> go{false};
  std::vector<std::thread> threads;
  for (int t = 0; t < 4; ++t)
  {
    threads.emplace_back(
      [&]()
      {
        while (!go.load())
        {
        }
        for (int i = 0; i < 200; ++i)
        {
          ch.publish("e", "frag");
        }
      });
  }
  // Concurrent subscribers + prune.
  for (int t = 0; t < 2; ++t)
  {
    threads.emplace_back(
      [&, t]()
      {
        while (!go.load())
        {
        }
        for (int i = 0; i < 100; ++i)
        {
          ch.subscribe(std::make_shared<SseStream>(srv, 1000 + t * 100 + i));
          ch.removeClosed();
        }
      });
  }
  go.store(true);
  for (auto &th : threads)
  {
    th.join();
  }
  REQUIRE(srv.writes.load() > 0); // no crash / no race; writes happened
}

TEST_CASE("conc: WsChannel publish racing disconnect (isSessionActive flip)", "[tsan][ws]")
{
  ConcWsServer srv;
  WsChannel ch("c");
  for (SessionId i = 1; i <= 16; ++i)
  {
    srv.setActive(i, true);
    ch.subscribe(srv, i);
  }

  std::atomic<bool> go{false};
  std::vector<std::thread> threads;
  for (int t = 0; t < 4; ++t)
  {
    threads.emplace_back(
      [&]()
      {
        while (!go.load())
        {
        }
        for (int i = 0; i < 200; ++i)
        {
          ch.publish("<li/>");
        }
      });
  }
  // Disconnect thread flips sessions inactive.
  threads.emplace_back(
    [&]()
    {
      while (!go.load())
      {
      }
      for (SessionId i = 1; i <= 16; ++i)
      {
        srv.setActive(i, false);
        std::this_thread::sleep_for(std::chrono::microseconds(50));
      }
    });
  go.store(true);
  for (auto &th : threads)
  {
    th.join();
  }
  REQUIRE(srv._sends.load() >= 0); // no race on the SessionId set
}

TEST_CASE("conc: SseManager heartbeat racing publish + disconnect removal", "[tsan][manager]")
{
  ConcSseServer srv;
  iora::core::TimerService timer;
  timer.start();
  SseManager mgr(srv, timer, std::chrono::milliseconds(2)); // very short heartbeat
  SseChannel ch("c");

  std::vector<std::shared_ptr<SseStream>> streams;
  for (SessionId i = 1; i <= 12; ++i)
  {
    auto s = std::make_shared<SseStream>(srv, i);
    streams.push_back(s);
    ch.subscribe(s);
    mgr.add(s);
  }

  std::atomic<bool> go{false};
  std::vector<std::thread> threads;
  threads.emplace_back(
    [&]()
    {
      while (!go.load())
      {
      }
      for (int i = 0; i < 300; ++i)
      {
        ch.publish("e", "frag");
      }
    });
  threads.emplace_back(
    [&]()
    {
      while (!go.load())
      {
      }
      for (auto &s : streams)
      {
        s->markClosed(); // disconnect-driven close racing the heartbeat
        std::this_thread::sleep_for(std::chrono::microseconds(100));
      }
    });
  go.store(true);
  for (auto &th : threads)
  {
    th.join();
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(10)); // let a few ticks run
  mgr.shutdown();
  timer.stop();
  REQUIRE(true); // TSAN clean: copy-then-iterate, no lock held during write
}

TEST_CASE("conc: disconnect observer racing publish is UAF-free", "[tsan][sse][uaf]")
{
  ConcSseServer srv;
  SseChannel ch("c");
  std::vector<std::shared_ptr<SseStream>> streams;
  for (SessionId i = 1; i <= 8; ++i)
  {
    auto s = std::make_shared<SseStream>(srv, i);
    streams.push_back(s);
    ch.subscribe(s);
  }

  std::atomic<bool> go{false};
  std::vector<std::thread> threads;
  threads.emplace_back(
    [&]()
    {
      while (!go.load())
      {
      }
      for (int i = 0; i < 500; ++i)
      {
        ch.publish("e", "frag"); // channel co-owns the streams -> no UAF
      }
    });
  threads.emplace_back(
    [&]()
    {
      while (!go.load())
      {
      }
      for (auto &s : streams)
      {
        s->markClosed();
      }
    });
  go.store(true);
  for (auto &th : threads)
  {
    th.join();
  }
  REQUIRE(true);
}

TEST_CASE("conc: onClose registration racing close fires EXACTLY once", "[tsan][close][rd22]")
{
  ConcSseServer srv;
  bool allOnce = true;
  for (int iter = 0; iter < 500; ++iter)
  {
    auto stream = std::make_shared<SseStream>(srv, 1);
    std::atomic<int> fires{0};
    std::atomic<bool> go{false};
    std::thread reg(
      [&]()
      {
        while (!go.load())
        {
        }
        stream->onClose([&fires]() { fires.fetch_add(1, std::memory_order_relaxed); });
      });
    std::thread clo(
      [&]()
      {
        while (!go.load())
        {
        }
        stream->close();
      });
    go.store(true);
    reg.join();
    clo.join();
    if (fires.load() != 1)
    {
      allOnce = false;
    }
  }
  REQUIRE(allOnce); // never zero (gauge leak), never two
}

TEST_CASE("conc: heartbeat racing graceful shutdown — no keepalive after shutting down",
          "[tsan][manager][shutdown]")
{
  ConcSseServer srv;
  iora::core::TimerService timer;
  timer.start();
  SseManager mgr(srv, timer, std::chrono::milliseconds(2));
  std::vector<std::shared_ptr<SseStream>> streams;
  for (SessionId i = 1; i <= 6; ++i)
  {
    auto s = std::make_shared<SseStream>(srv, i);
    streams.push_back(s);
    mgr.add(s);
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(20)); // let keepalives flow
  mgr.shutdown();                                              // sets _draining, writes ':shutting down', closes
  std::this_thread::sleep_for(std::chrono::milliseconds(20)); // any late tick is a no-op
  timer.stop();

  bool ok = true;
  bool sawAnyKeepalive = false;
  for (SessionId i = 1; i <= 6; ++i)
  {
    const std::string b = srv.bytesFor(i);
    if (b.find(": keepalive\n\n") != std::string::npos)
    {
      sawAnyKeepalive = true;
    }
    const auto sd = b.rfind(": shutting down\n\n");
    if (sd == std::string::npos)
    {
      ok = false; // every stream must have received the final marker
      continue;
    }
    // No ':keepalive' may appear AFTER the ':shutting down' marker (thread-H3).
    if (b.find(": keepalive\n\n", sd) != std::string::npos)
    {
      ok = false;
    }
  }
  REQUIRE(ok);
  // thread-L2 robustness: fail loudly if the heartbeat never fired (otherwise the
  // "no keepalive after shutting-down" assertion would pass vacuously).
  REQUIRE(sawAnyKeepalive);
}

TEST_CASE("conc: publish racing graceful shutdown — streams closed, no dead-server deref",
          "[tsan][manager][shutdown]")
{
  // v1 ties stream lifetime to the server (knownLimitations): the server (and
  // thus each stream's _server back-pointer) outlives all publishes here, and the
  // streams are shared_ptr-co-owned by the channel, so no dangling deref is
  // possible. This case asserts that — under TSAN — concurrent publish racing
  // shutdown is race-free AND that shutdown actually closes every stream (so a
  // post-shutdown publish writes nothing), rather than asserting a vacuous true.
  ConcSseServer srv;
  iora::core::TimerService timer;
  timer.start();
  SseChannel ch("c");
  std::vector<std::shared_ptr<SseStream>> streams;
  {
    SseManager mgr(srv, timer, std::chrono::milliseconds(2));
    for (SessionId i = 1; i <= 8; ++i)
    {
      auto s = std::make_shared<SseStream>(srv, i);
      streams.push_back(s);
      ch.subscribe(s);
      mgr.add(s);
    }
    std::atomic<bool> go{false};
    std::thread pub(
      [&]()
      {
        while (!go.load())
        {
        }
        for (int i = 0; i < 500; ++i)
        {
          ch.publish("e", "frag");
        }
      });
    go.store(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    mgr.shutdown();
    pub.join();
    timer.stop();
  }
  // Every stream was closed by shutdown.
  for (auto &s : streams)
  {
    REQUIRE_FALSE(s->isOpen());
  }
  // A post-shutdown publish writes nothing (all streams closed).
  const long writesBefore = srv.writes.load();
  ch.publish("e", "frag");
  REQUIRE(srv.writes.load() == writesBefore);
}

TEST_CASE("conc: stream use_count returns to baseline after disconnect + removal",
          "[tsan][sse][lifetime]")
{
  ConcSseServer srv;
  SseChannel ch("c");
  iora::core::TimerService timer;
  timer.start();
  SseManager mgr(srv, timer, std::chrono::milliseconds(50));

  auto stream = std::make_shared<SseStream>(srv, 1); // local ref (count 1)
  ch.subscribe(stream);                              // channel ref (2)
  mgr.add(stream);                                   // manager ref (3)
  std::function<void()> observerClosure = [stream]() {}; // simulate observe strong ref (4)
  REQUIRE(stream.use_count() == 4);

  stream->markClosed();
  ch.removeClosed();   // channel drops its ref
  mgr.remove(stream);  // manager drops its ref
  observerClosure = nullptr; // engine auto-purge releases the closure
  REQUIRE(stream.use_count() == 1); // only the local ref remains
  mgr.shutdown();
  timer.stop();
}

TEST_CASE("conc: Date formatter concurrency (reentrant gmtime, thread-H4)", "[tsan][date]")
{
  using iora::network::detail::formatHttpDate;
  // Distinct known epochs and their expected IMF-fixdate strings.
  struct Case
  {
    std::time_t epoch;
    std::string expected;
  };
  const std::vector<Case> cases = {
    {0, "Thu, 01 Jan 1970 00:00:00 GMT"},
    {1700000000, "Tue, 14 Nov 2023 22:13:20 GMT"},
    {1000000000, "Sun, 09 Sep 2001 01:46:40 GMT"},
    {1234567890, "Fri, 13 Feb 2009 23:31:30 GMT"},
  };

  std::atomic<bool> go{false};
  std::atomic<int> mismatches{0};
  std::vector<std::thread> threads;
  for (int t = 0; t < 8; ++t)
  {
    threads.emplace_back(
      [&, t]()
      {
        while (!go.load())
        {
        }
        const Case &c = cases[t % cases.size()];
        for (int i = 0; i < 2000; ++i)
        {
          if (formatHttpDate(c.epoch) != c.expected)
          {
            mismatches.fetch_add(1, std::memory_order_relaxed);
          }
        }
      });
  }
  go.store(true);
  for (auto &th : threads)
  {
    th.join();
  }
  REQUIRE(mismatches.load() == 0); // no torn Date; reentrant conversion
}
