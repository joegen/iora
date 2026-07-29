// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for the HttpClient cancellation seam: cancelInFlight(), the
// publish-then-recheck race fix, and the typed HttpClientCancelledError.
// Tracker: 2026-07-26-12 (HttpClient cancellation seam). A blocking client
// destructor (tracker 2026-07-26-2 phase 3) depends on cancellation being TOTAL
// and prompt: a request wedged in the receive loop (requestTimeout does NOT
// bound the exchange) must unwind when another thread cancels it.
//
// Catch2 assertion macros are invoked ONLY on the main thread; worker threads
// record results into atomics / a std::future and the main thread asserts after
// a BOUNDED wait (never an unbounded join, so a regressed mutation fails on the
// test's own bound, not the 30 s transport timeout). Run under TSan (setarch -R).

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/network/http_client.hpp>
#include <iora/network/transport_impl.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace iora::network;
using namespace std::chrono_literals;

namespace
{

// A minimal raw-HTTP test server built on the iora Transport. The responder is
// invoked once per COMPLETE request (a delivery containing CRLFCRLF), with a
// 0-based request ordinal — so a keep-alive REUSED connection's second request
// re-fires the responder (a per-connection dedup would leave that path dead).
// onClose bumps a counter so a test can assert "the server observed the close".
// Named distinctly from iora_test_http_client_lease.cpp's POSIX-socket RawServer.
class TransportRawServer
{
public:
  explicit TransportRawServer(std::function<void(TransportRawServer &, SessionId, int)> responder)
      : _responder(std::move(responder))
  {
    TransportConfig cfg;
    cfg.protocol = Protocol::TCP;
    _server = Transport::tcp(cfg);
    _server->onAccept([this](SessionId, const TransportAddress &) { ++_accepts; });
    _server->onClose([this](SessionId, const TransportErrorInfo &) { ++_closes; });
    _server->onData(
      [this](SessionId sid, iora::core::BufferView data, std::chrono::steady_clock::time_point)
      {
        // Count a request per complete head (CRLFCRLF). Localhost tiny requests
        // (GET / small POST) arrive whole, and this re-fires on keep-alive reuse.
        std::string bytes(reinterpret_cast<const char *>(data.data()), data.size());
        if (bytes.find("\r\n\r\n") == std::string::npos) { return; }
        const int ordinal = _requests.fetch_add(1);
        _responder(*this, sid, ordinal);
      });
    if (_server->start().isErr()) { throw std::runtime_error("TransportRawServer start failed"); }
    auto lr = _server->addListener("127.0.0.1", 0);
    if (lr.isErr()) { throw std::runtime_error("TransportRawServer listen failed"); }
    _port = _server->getListenerAddress(lr.value()).port;
  }

  ~TransportRawServer()
  {
    // Order matters: stop the flag, then stop the server (no more onData -> no
    // new dribblers spawned and existing send()s fail fast), then JOIN every
    // dribbler so no detached thread outlives this fixture and reads freed
    // members in a later test case.
    _stopDribble = true;
    _server->stop();
    std::lock_guard<std::mutex> lk(_threadsMu);
    for (auto &t : _dribblers)
    {
      if (t.joinable()) { t.join(); }
    }
  }

  std::uint16_t port() const { return _port; }
  std::string url(const std::string &path = "/rpc") const
  {
    return "http://127.0.0.1:" + std::to_string(_port) + path;
  }
  int accepts() const { return _accepts.load(); }
  int requests() const { return _requests.load(); }
  int closes() const { return _closes.load(); }
  bool headersSent() const { return _headersSent.load(); }

  void sendRaw(SessionId sid, const std::string &bytes)
  {
    _server->send(sid, iora::core::BufferView{
                          reinterpret_cast<const std::uint8_t *>(bytes.data()), bytes.size()});
  }

  // Send `bytes` (a header block, marking headersSent), then dribble one
  // byte/200ms so the client stays parked in the receive loop with headers
  // already framed. The dribbler is OWNED (joined by ~TransportRawServer), never
  // detached.
  void sendThenDribble(SessionId sid, const std::string &bytes)
  {
    sendRaw(sid, bytes);
    _headersSent = true;
    std::lock_guard<std::mutex> lk(_threadsMu);
    _dribblers.emplace_back(
      [this, sid]
      {
        for (int i = 0; i < 600 && !_stopDribble.load(); ++i)
        {
          std::this_thread::sleep_for(200ms);
          const char c = 'x';
          if (!_server->send(sid, iora::core::BufferView{
                                    reinterpret_cast<const std::uint8_t *>(&c), 1}))
          {
            return;
          }
        }
      });
  }

private:
  std::function<void(TransportRawServer &, SessionId, int)> _responder;
  std::shared_ptr<Transport> _server;
  std::uint16_t _port{0};
  std::atomic<int> _accepts{0};
  std::atomic<int> _requests{0};
  std::atomic<int> _closes{0};
  std::atomic<bool> _headersSent{false};
  std::atomic<bool> _stopDribble{false};
  std::mutex _threadsMu;
  std::vector<std::thread> _dribblers;
};

// Responders.
const auto silent = [](TransportRawServer &, SessionId, int) {};
const auto slowloris = [](TransportRawServer &s, SessionId sid, int)
{ s.sendThenDribble(sid, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"); };

// Bounded wait on a future; returns true if ready within `d`.
template <typename T> bool ready(std::future<T> &f, std::chrono::milliseconds d)
{
  return f.wait_for(d) == std::future_status::ready;
}

// Bounded poll on a predicate; returns true if it became true within `d`.
template <typename Pred> bool waitUntil(Pred p, std::chrono::milliseconds d)
{
  auto deadline = std::chrono::steady_clock::now() + d;
  while (std::chrono::steady_clock::now() < deadline)
  {
    if (p()) { return true; }
    std::this_thread::sleep_for(5ms);
  }
  return p();
}

} // namespace

// ---------------------------------------------------------------------------
// task-1.8 CORE (port of tools/proofs/cancel_proof.cpp, BOUNDED wait):
// Transport::close(sid) from another thread cancels a parked receiveSync.
// ---------------------------------------------------------------------------
TEST_CASE("Transport::close cancels a parked receiveSync", "[cancel][core]")
{
  TransportConfig scfg;
  scfg.protocol = Protocol::TCP;
  auto server = Transport::tcp(scfg);
  REQUIRE(server->start().isOk());
  auto lr = server->addListener("127.0.0.1", 0);
  REQUIRE(lr.isOk());
  auto port = server->getListenerAddress(lr.value()).port;

  TransportConfig ccfg;
  ccfg.protocol = Protocol::TCP;
  auto client = Transport::tcp(ccfg);
  REQUIRE(client->start().isOk());
  auto cr = client->connectSync("127.0.0.1", port, TlsMode::None, 2000ms);
  REQUIRE(cr.isOk());
  SessionId sid = cr.value();
  REQUIRE(client->setReadMode(sid, ReadMode::Sync));

  std::atomic<int> code{-1};
  auto fut = std::async(std::launch::async,
                        [&]
                        {
                          char buf[8192];
                          std::size_t len = sizeof(buf);
                          auto r = client->receiveSync(sid, buf, len, 30000ms);
                          code = r.isErr() ? static_cast<int>(r.error().code) : -1;
                        });

  std::this_thread::sleep_for(300ms);
  REQUIRE(client->close(sid)); // the primitive under test

  REQUIRE(ready(fut, 2000ms)); // MUTATION: without close() this expires the bound
  fut.get();
  REQUIRE(code.load() != static_cast<int>(TransportError::Timeout));

  client->stop();
  server->stop();
}

// ---------------------------------------------------------------------------
// task-1.2: cancelInFlight() unwinds a wedged HttpClient exchange promptly and
// is idempotent.
// ---------------------------------------------------------------------------
TEST_CASE("cancelInFlight unwinds a wedged exchange and is idempotent", "[cancel][cancelinflight]")
{
  TransportRawServer server(slowloris);

  HttpClient::Config cfg; // requestTimeout is per-iteration, NOT a total deadline
  HttpClient client(cfg);

  std::atomic<bool> cancelled{false};
  auto fut = std::async(std::launch::async,
                        [&]
                        {
                          try
                          {
                            client.postJson(server.url(), iora::parsers::Json::object(), {}, 0);
                          }
                          catch (const HttpClientCancelledError &)
                          {
                            cancelled = true;
                          }
                          catch (const std::exception &)
                          {
                          }
                        });

  REQUIRE(waitUntil([&] { return server.headersSent(); }, 2000ms));
  REQUIRE_FALSE(ready(fut, 0ms)); // still blocked: requestTimeout is no deadline
  client.cancelInFlight();

  REQUIRE(ready(fut, 2000ms)); // MUTATION: remove the close-loop -> hangs to timeout
  fut.get();
  REQUIRE(cancelled.load());

  // Idempotent: a second call (and the transitive one via ~HttpClient) is a no-op.
  REQUIRE_NOTHROW(client.cancelInFlight());
}

// ---------------------------------------------------------------------------
// task-1.5: a request issued AFTER cancelInFlight() throws HttpClientCancelledError
// and creates no transport / makes no connection (observable: server sees zero
// accepts).
// ---------------------------------------------------------------------------
TEST_CASE("request after cancelInFlight is refused with no connection", "[cancel][refused]")
{
  TransportRawServer server(silent);
  HttpClient::Config cfg;
  HttpClient client(cfg);

  client.cancelInFlight();

  auto t0 = std::chrono::steady_clock::now();
  REQUIRE_THROWS_AS(client.get(server.url()), HttpClientCancelledError);
  auto elapsed =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);

  REQUIRE(elapsed < 200ms);       // immediate — no connect attempt
  REQUIRE(server.accepts() == 0); // observable proxy: no transport built / no connect
}

// ---------------------------------------------------------------------------
// task-1.6: a cancelled idempotent GET is NEVER retried — the exchange is not
// re-sent and zero backoff sleeps occur. Post-cancel timing is the discriminator
// (retries would add 100+200+400 ms of backoff before acquireLease intercepts).
// ---------------------------------------------------------------------------
TEST_CASE("a cancelled idempotent GET is not retried", "[cancel][no-retry]")
{
  TransportRawServer server(slowloris);

  HttpClient::Config cfg;
  HttpClient client(cfg);

  std::atomic<bool> cancelled{false};
  auto fut = std::async(std::launch::async,
                        [&]
                        {
                          try
                          {
                            client.get(server.url(), {}, /*retries=*/3); // idempotent
                          }
                          catch (const HttpClientCancelledError &)
                          {
                            cancelled = true;
                          }
                          catch (const std::exception &)
                          {
                          }
                        });

  REQUIRE(waitUntil([&] { return server.headersSent(); }, 2000ms));
  auto tCancel = std::chrono::steady_clock::now();
  client.cancelInFlight();

  REQUIRE(ready(fut, 2000ms));
  fut.get();
  auto postCancel =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tCancel);

  REQUIRE(cancelled.load());
  REQUIRE(server.requests() == 1); // the exchange is never re-sent to the server
  // MUTATION: remove performRequest's HttpClientCancelledError guard -> the
  // cancelled idempotent GET is retried; retries 2..4 throw immediately at
  // acquireLease (never reaching the server) but each is preceded by a backoff
  // sleep of 100+200+400 ms. With the guard the unwind is a single ~ms wakeup.
  REQUIRE(postCancel < 300ms);
}

// ---------------------------------------------------------------------------
// task-1.6 (negative): a lease-acquire TIMEOUT (not shutdown) still raises a
// retry-eligible std::runtime_error, NOT HttpClientCancelledError.
// ---------------------------------------------------------------------------
TEST_CASE("lease-acquire timeout is not a cancellation", "[cancel][lease-timeout]")
{
  TransportRawServer server(slowloris);

  HttpClient::Config cfg;
  cfg.leaseAcquireTimeout = 300ms; // second same-host request times out fast
  HttpClient client(cfg);

  // Request 1 wedges and holds the per-host lease.
  auto held = std::async(std::launch::async,
                         [&]
                         {
                           try
                           {
                             client.get(server.url(), {}, 0);
                           }
                           catch (const std::exception &)
                           {
                           }
                         });
  REQUIRE(waitUntil([&] { return server.headersSent(); }, 2000ms)); // request 1 holds the lease

  // Request 2 to the same host:port cannot acquire the lease -> timeout.
  bool wasCancelled = false;
  bool wasRuntime = false;
  try
  {
    client.get(server.url(), {}, 0);
  }
  catch (const HttpClientCancelledError &)
  {
    wasCancelled = true;
  }
  catch (const std::runtime_error &)
  {
    wasRuntime = true;
  }
  REQUIRE(wasRuntime);
  REQUIRE_FALSE(wasCancelled);

  client.cancelInFlight(); // release request 1
  REQUIRE(ready(held, 2000ms));
  held.get();
}

// ---------------------------------------------------------------------------
// task-1.7 (THE hazard): a genuinely close-delimited response (no Content-Length,
// no Transfer-Encoding) cancelled mid-body must throw HttpClientCancelledError,
// NOT return a truncated 200. Mutation: remove the close-delimited guard ->
// truncated 200 returned. Barrier: the server confirms headers were flushed AND
// the request is observably parked (a close-delimited request completes ONLY on
// close, so "still in-flight after headers flushed" == headers framed).
// ---------------------------------------------------------------------------
TEST_CASE("close-delimited response cancelled mid-body is not a truncated 200",
          "[cancel][close-delimited]")
{
  // Rule 8 (RFC 9112 §6.3): 200 with a body and NO Content-Length / NO
  // Transfer-Encoding -> CloseDelimited.
  TransportRawServer server([](TransportRawServer &s, SessionId sid, int)
                            { s.sendThenDribble(sid, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nPARTIAL"); });

  HttpClient::Config cfg;
  HttpClient client(cfg);

  std::atomic<int> status{-1};
  std::atomic<bool> cancelled{false};
  auto fut = std::async(std::launch::async,
                        [&]
                        {
                          try
                          {
                            auto r = client.get(server.url(), {}, 0);
                            status = r.statusCode;
                          }
                          catch (const HttpClientCancelledError &)
                          {
                            cancelled = true;
                          }
                          catch (const std::exception &)
                          {
                          }
                        });

  // Client-observed barrier: server flushed headers AND the request is still
  // parked (headers framed, waiting for the never-arriving close/body).
  REQUIRE(waitUntil([&] { return server.headersSent(); }, 2000ms));
  // A close-delimited response completes ONLY on close, so "still in-flight
  // 100 ms after the headers were flushed" proves the client framed the headers
  // (headersDone==true, mode==CloseDelimited) and is parked, not completed.
  REQUIRE_FALSE(ready(fut, 100ms));
  client.cancelInFlight();

  REQUIRE(ready(fut, 2000ms));
  fut.get();
  REQUIRE(cancelled.load());
  REQUIRE(status.load() == -1); // MUTATION: without the guard a truncated 200 returns
}

// ---------------------------------------------------------------------------
// task-1.7 companion: a Content-Length response cancelled mid-body throws
// HttpClientCancelledError (not a truncation runtime_error). retries=0 so the
// mutation (remove the guard) escapes as a plain runtime_error and REQUIRE
// (cancelled) fails — matching the chunked companion's discriminating shape.
// (retries>0 would let acquireLease's shutdown throw mask the mutation.)
// ---------------------------------------------------------------------------
TEST_CASE("content-length response cancelled mid-body is cancelled", "[cancel][content-length]")
{
  TransportRawServer server(slowloris);

  HttpClient::Config cfg;
  HttpClient client(cfg);

  std::atomic<bool> cancelled{false};
  auto fut = std::async(std::launch::async,
                        [&]
                        {
                          try
                          {
                            client.get(server.url(), {}, /*retries=*/0);
                          }
                          catch (const HttpClientCancelledError &)
                          {
                            cancelled = true;
                          }
                          catch (const std::exception &)
                          {
                          }
                        });

  REQUIRE(waitUntil([&] { return server.headersSent(); }, 2000ms));
  client.cancelInFlight();

  REQUIRE(ready(fut, 2000ms));
  fut.get();
  REQUIRE(cancelled.load());
  REQUIRE(server.requests() == 1);
}

// ---------------------------------------------------------------------------
// task-1.7 companion: a chunked response cancelled before the terminating
// 0-chunk throws HttpClientCancelledError (not a truncation runtime_error).
// ---------------------------------------------------------------------------
TEST_CASE("chunked response cancelled mid-body is cancelled", "[cancel][chunked]")
{
  TransportRawServer server(
    [](TransportRawServer &s, SessionId sid, int)
    { s.sendThenDribble(sid, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n"); });

  HttpClient::Config cfg;
  HttpClient client(cfg);

  std::atomic<bool> cancelled{false};
  auto fut = std::async(std::launch::async,
                        [&]
                        {
                          try
                          {
                            client.get(server.url(), {}, 0);
                          }
                          catch (const HttpClientCancelledError &)
                          {
                            cancelled = true;
                          }
                          catch (const std::exception &)
                          {
                          }
                        });

  REQUIRE(waitUntil([&] { return server.headersSent(); }, 2000ms));
  client.cancelInFlight();

  REQUIRE(ready(fut, 2000ms));
  fut.get();
  REQUIRE(cancelled.load());
}

// ---------------------------------------------------------------------------
// task-1.8 (b): a cancel on a request REUSING a warm cached connection is a
// clean cancellation. Request 1 completes with a keep-alive response (warming
// the cache); request 2 reuses the SAME connection (accepts stays 1) and parks
// mid-body on the slowloris; the cancel closes it (server observes the close).
// ---------------------------------------------------------------------------
TEST_CASE("cancel on a reused cached connection", "[cancel][cache-hit]")
{
  TransportRawServer server(
    [](TransportRawServer &s, SessionId sid, int ordinal)
    {
      if (ordinal == 0)
      {
        // First request: a complete, reusable keep-alive response.
        s.sendRaw(sid, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
      }
      else
      {
        // Second request on the REUSED connection: wedge it mid-body.
        s.sendThenDribble(sid, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n");
      }
    });

  HttpClient::Config cfg;
  cfg.reuseConnections = true;
  HttpClient client(cfg);

  auto r1 = client.get(server.url(), {}, 0);
  REQUIRE(r1.statusCode == 200);

  std::atomic<bool> cancelled{false};
  auto fut = std::async(std::launch::async,
                        [&]
                        {
                          try
                          {
                            client.get(server.url(), {}, 0);
                          }
                          catch (const HttpClientCancelledError &)
                          {
                            cancelled = true;
                          }
                          catch (const std::exception &)
                          {
                          }
                        });

  REQUIRE(waitUntil([&] { return server.headersSent(); }, 2000ms)); // request 2's headers flushed
  client.cancelInFlight();
  REQUIRE(ready(fut, 2000ms));
  fut.get();
  REQUIRE(cancelled.load());
  REQUIRE(server.accepts() == 1);  // exactly one TCP connection => request 2 REUSED it
  REQUIRE(server.requests() == 2); // and the reuse branch actually executed
  REQUIRE(waitUntil([&] { return server.closes() >= 1; }, 2000ms)); // server observed the close
}

// ---------------------------------------------------------------------------
// task-1.8 (a): a cancel while the request is parked in connectSync (a
// black-holed peer) unwinds bounded by connectTimeout and surfaces as
// HttpClientCancelledError (the pre-send generic-catch retype; validates the
// M-8 drain bound: cancelInFlight does NOT wake a connect-parked request, it
// unwinds on its own connectTimeout and is then reclassified as cancelled
// because _closing is set (the pre-send generic-catch retype). 192.0.2.1
// (RFC 5737 TEST-NET-1, non-routable) black-holes the SYN so connectSync parks
// until connectTimeout — verified on this host (a loopback dead port instead
// fast-refuses and would not exercise the parked path).
// ---------------------------------------------------------------------------
TEST_CASE("cancel while parked in connectSync is bounded and cancelled", "[cancel][connect]")
{
  // CI NOTE: this case requires 192.0.2.1 to black-hole the SYN (connect hangs
  // to connectTimeout). Do NOT add a null-route or REJECT rule for 192.0.2.1 /
  // RFC 5737 TEST-NET-1 on the test host, or the connect would fast-fail before
  // the cancel lands and the request would surface as a (retryable) not-sent
  // error instead of the cancellation this case verifies.
  HttpClient::Config cfg;
  cfg.connectTimeout = 1000ms;
  HttpClient client(cfg);
  const std::string url = "http://192.0.2.1:80/rpc"; // non-routable -> connect hangs

  std::atomic<bool> cancelled{false};
  std::atomic<bool> otherThrow{false};
  auto t0 = std::chrono::steady_clock::now();
  auto fut = std::async(std::launch::async,
                        [&]
                        {
                          try
                          {
                            client.get(url, {}, 0);
                          }
                          catch (const HttpClientCancelledError &)
                          {
                            cancelled = true;
                          }
                          catch (const std::exception &)
                          {
                            otherThrow = true;
                          }
                        });

  std::this_thread::sleep_for(50ms); // land the cancel while parked in connect
  client.cancelInFlight();

  // Bounded by connectTimeout (cancel does NOT wake a connect-parked request).
  REQUIRE(ready(fut, 3000ms));
  fut.get();
  auto elapsed =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
  REQUIRE(elapsed < 2500ms); // did not hang; unwound near connectTimeout

  // The connect is still parked (black-holed) when _closing is set, so the
  // failure is retyped to a cancellation, not a retryable HttpRequestNotSentError.
  REQUIRE(cancelled.load());
  REQUIRE_FALSE(otherThrow.load());
}

// ---------------------------------------------------------------------------
// task-1.3 (M-7): cleanup()/~HttpClient still tears the client down without
// hanging even after a live exchange, and the server observes the connection
// close. Positive teardown assertion (the lock scope of cleanup() narrowed).
// ---------------------------------------------------------------------------
TEST_CASE("client teardown after a live request closes the connection promptly",
          "[cancel][teardown]")
{
  TransportRawServer server(
    [](TransportRawServer &s, SessionId sid, int)
    { s.sendRaw(sid, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"); });

  auto t0 = std::chrono::steady_clock::now();
  {
    HttpClient::Config cfg;
    cfg.reuseConnections = true;
    HttpClient client(cfg);
    auto r = client.get(server.url(), {}, 0);
    REQUIRE(r.statusCode == 200);
  } // ~HttpClient -> cleanup() -> cancelInFlight() + stop transport + stop dns
  auto elapsed =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);

  REQUIRE(elapsed < 2000ms); // teardown returned promptly (no hang)
  REQUIRE(waitUntil([&] { return server.closes() >= 1; }, 2000ms)); // transport torn down
}

// ---------------------------------------------------------------------------
// task-1.4 (C-1 regression, run under TSan): cancelling concurrently with connect
// establishment must NEVER surface as a retryable HttpRequestNotSentError —
// whenever the request throws due to the cancellation it must be
// HttpClientCancelledError, and the publish-recheck must not leak a session
// (the server sees every opened connection closed). Repeated to exercise the
// publish-recheck window and the post-publish generic-catch recheck (per the
// tracker's MED-1 disposition, the publish-window itself is covered
// probabilistically here).
// ---------------------------------------------------------------------------
TEST_CASE("concurrent cancel during connect never laundered to retryable", "[cancel][race]")
{
  for (int i = 0; i < 40; ++i)
  {
    TransportRawServer server(silent);
    HttpClient::Config cfg;
    cfg.connectTimeout = 800ms;
    HttpClient client(cfg);

    std::atomic<bool> notSentLeaked{false};
    std::atomic<bool> cancelledType{false};
    std::atomic<bool> succeeded{false};
    auto fut = std::async(std::launch::async,
                          [&]
                          {
                            try
                            {
                              client.get(server.url(), {}, 0);
                              succeeded = true;
                            }
                            catch (const HttpClientCancelledError &)
                            {
                              cancelledType = true;
                            }
                            catch (const HttpRequestNotSentError &)
                            {
                              notSentLeaked = true; // C-1: a cancel laundered to retryable
                            }
                            catch (const std::exception &)
                            {
                            }
                          });

    std::this_thread::sleep_for(1ms); // fire the cancel in the connect/publish window
    client.cancelInFlight();

    REQUIRE(ready(fut, 3000ms));
    fut.get();
    // C-1: a cancellation is NEVER delivered as the retryable not-sent type.
    REQUIRE_FALSE(notSentLeaked.load());
    // The request either was cancelled (the common case here) or completed on
    // the silent server before the cancel landed (rare); it must not leak a
    // session either way — every connection the server accepted it also saw
    // closed by the time the client is destroyed at scope exit.
    (void)cancelledType;
    (void)succeeded;
    // No leaked session: every accepted connection is eventually closed.
    REQUIRE(waitUntil([&] { return server.closes() >= server.accepts(); }, 2000ms));
  }
}
