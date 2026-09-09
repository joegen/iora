// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// THE ACCEPTANCE TEST (tracker 2026-07-26-1 phase-8, task-8.1). Composes
// network::HttpServer + rpc::JsonRpcServer + rpc::JsonRpcHttpEndpoint +
// rpc::JsonRpcClient and performs a real round trip, a notification (204), and a
// batch — with no plugin/service host and no dynamically loaded module. Its
// cleanliness IS the deliverable: the file must not name the old service host,
// its single-module loader, the exported-api call path, or a shared-object path
// (the tracker's grep guard over this file returns nothing).
//
// It also verifies the D-LIFETIME teardown precondition (task-3.3, Reversal A):
// the JsonRpcServer is declared before the HttpServer and the endpoint (which
// holds raw references to both) is destroyed first. The case that MATTERS holds
// a dispatch IN-FLIGHT across HttpServer::stop() so the 2 s drain-wait — the
// WHOLE mitigation for the accepted raw-pointer teardown UAF — is actually
// exercised, never left vacuous (M1). It also composes a STATEFUL
// JsonRpcHttpOptions.tokenValidator and asserts the captured state stays alive
// for that late dispatch (M4).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/core/string_utils.hpp"
#include "iora/core/thread_pool.hpp"
#include "iora/network/http_server.hpp"
#include "iora/rpc/jsonrpc_client.hpp"
#include "iora/rpc/jsonrpc_http.hpp"
#include "iora/rpc/jsonrpc_server.hpp"

#include "iora_test_net_utils.hpp"  // testnet::getFreePortTCP
#include "jsonrpc_test_support.hpp" // testrpc::ComposedRpcServer

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace std::chrono_literals;

using iora::parsers::Json;
using iora::rpc::BatchItem;
using iora::rpc::Config;
using iora::rpc::JsonRpcClient;
using iora::rpc::JsonRpcHttpEndpoint;
using iora::rpc::JsonRpcHttpOptions;
using iora::rpc::JsonRpcServer;
using iora::rpc::RpcContext;

namespace
{
const std::vector<std::pair<std::string, std::string>> kNoHeaders{};

/// \brief maxRetries=0 so each call is a single, observable round trip; a
/// requestTimeout comfortably longer than the M1 in-flight hold below.
Config e2eConfig()
{
  Config cfg;
  cfg.requestTimeout = 5s;
  cfg.connectionTimeout = 2s;
  cfg.maxRetries = 0;
  cfg.initialRetryDelay = 1ms;
  cfg.maxRetryDelay = 2ms;
  return cfg;
}
} // namespace

TEST_CASE("jsonrpc e2e: round trip + notification (204) + batch, composed directly",
          "[jsonrpc_e2e]")
{
  // Declared before `rpc`, so it is destroyed AFTER it — and ComposedRpcServer's
  // dtor drains in-flight handlers before returning, so every handler that
  // captures &notifyHits has finished while notifyHits is still alive. A plain
  // stack atomic is therefore safe here; no shared_ptr indirection is needed.
  std::atomic<int> notifyHits{0};
  testrpc::ComposedRpcServerOptions opts;
  opts.registerMethods = [&notifyHits](JsonRpcServer &server)
  {
    server.registerMethod("add", [](const Json &p, RpcContext &)
                          { return Json(p["a"].get<int>() + p["b"].get<int>()); });
    server.registerMethod("echo", [](const Json &p, RpcContext &) { return p; });
    server.registerMethod("sink",
                          [&notifyHits](const Json &, RpcContext &)
                          {
                            notifyHits.fetch_add(1, std::memory_order_relaxed);
                            return Json(nullptr);
                          });
  };
  testrpc::ComposedRpcServer rpc(std::move(opts));

  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, e2eConfig());

  SECTION("single request round trip")
  {
    Json params;
    params["a"] = 2;
    params["b"] = 3;
    Json result = client.call(rpc.url(), "add", params, kNoHeaders);
    REQUIRE(result.get<int>() == 5);
  }

  SECTION("notification reaches the handler and the client treats it as success")
  {
    // The handler runs synchronously within the request BEFORE the endpoint
    // emits its response, so the count is 1 the moment notify() returns.
    REQUIRE_NOTHROW(client.notify(rpc.url(), "sink", Json("evt"), kNoHeaders));
    REQUIRE(notifyHits.load(std::memory_order_relaxed) == 1);
    auto stats = client.getStats();
    REQUIRE(stats.notificationRequests == 1);
    REQUIRE(stats.successfulRequests == 1);
    REQUIRE(stats.retriedRequests == 0);
  }

  SECTION("a notification is answered with a bodyless HTTP 204 on the wire")
  {
    // task-8.1 deliverable: the notification is answered with HTTP 204. The
    // client API collapses every 2xx to void success, so it cannot distinguish
    // 204 from 200-empty — assert the wire status directly over a raw socket. A
    // JSON-RPC notification (no "id") MUST yield 204 with no body and no
    // Content-Length/Content-Type entity headers (RFC 9110 §15.3.5 / §8.6).
    const std::string body = R"({"jsonrpc":"2.0","method":"sink","params":"evt"})";
    const std::string req = "POST /rpc HTTP/1.1\r\n"
                            "Host: localhost:" +
                            std::to_string(rpc.port()) +
                            "\r\n"
                            "Content-Type: application/json\r\n"
                            "Content-Length: " +
                            std::to_string(body.size()) +
                            "\r\n"
                            "Connection: close\r\n\r\n" +
                            body;
    const std::string resp = testnet::rawHttpRequest(rpc.port(), req);
    // Anchored status-line match (offset 0, trailing space) so it cannot match a
    // header value or a hypothetical 2040-2049 code.
    REQUIRE(resp.rfind("HTTP/1.1 204 ", 0) == 0);
    const auto headerEnd = resp.find("\r\n\r\n");
    REQUIRE(headerEnd != std::string::npos);
    const std::string headers = iora::core::StringUtils::toLower(resp.substr(0, headerEnd));
    // 204 carries no entity/framing headers (case-insensitive).
    REQUIRE(headers.find("content-length:") == std::string::npos);
    REQUIRE(headers.find("content-type:") == std::string::npos);
    REQUIRE(headers.find("transfer-encoding:") == std::string::npos);
    // …and zero residual octets after the header terminator (a bodyless 204).
    REQUIRE(resp.size() == headerEnd + 4);
  }

  SECTION("batch returns one result per item, in order")
  {
    std::vector<BatchItem> items;
    Json p1;
    p1["a"] = 10;
    p1["b"] = 1;
    Json p2;
    p2["a"] = 20;
    p2["b"] = 2;
    items.emplace_back("add", p1, 1u);
    items.emplace_back("add", p2, 2u);
    auto results = client.callBatch(rpc.url(), items, kNoHeaders);
    REQUIRE(results.size() == 2);
    REQUIRE(results[0].get<int>() == 11);
    REQUIRE(results[1].get<int>() == 22);
  }

  SECTION("mixed batch: request keeps its result, notification slot is null (JSON-RPC 2.0 §6)")
  {
    // A batch of one request (has id) + one notification (no id). Per §6 the
    // server returns a response only for the request; the client re-aligns
    // results to REQUEST ORDER and fills the notification's slot with null —
    // exercising both the notification-hole handling and by-id correlation.
    std::vector<BatchItem> items;
    Json p;
    p["a"] = 7;
    p["b"] = 5;
    items.emplace_back("add", p, 1u);        // request (id = 1)
    items.emplace_back("sink", Json("evt")); // notification (no id)
    auto results = client.callBatch(rpc.url(), items, kNoHeaders);
    REQUIRE(results.size() == 2);
    REQUIRE(results[0].get<int>() == 12); // request result, in request order
    REQUIRE(results[1].is_null());        // notification produced no response
  }
}

TEST_CASE("jsonrpc e2e: HttpServer::stop() drains an in-flight dispatch before teardown "
          "(D-LIFETIME, M1 in-flight, M4 stateful validator)",
          "[jsonrpc_e2e][teardown]")
{
  // Coordination between the blocking handler and the test threads.
  std::mutex m;
  std::condition_variable cv;
  bool release = false;
  std::atomic<bool> handlerEntered{false};
  std::atomic<int> seq{0};
  std::atomic<int> handlerOrder{0};
  std::string observedSubject;

  // M4: a STATEFUL validator capturing a token store. Its captured state must
  // stay alive for the dispatch held across stop() and its teardown.
  const std::string kToken = "s3cr3t-e2e";
  const std::string kSubject = "acct-42";
  auto tokens = std::make_shared<std::map<std::string, std::string>>();
  (*tokens)[kToken] = kSubject;

  // D-LIFETIME (task-3.3, Reversal A): JsonRpcServer declared BEFORE the
  // HttpServer; the endpoint (which holds raw references to both) is a
  // unique_ptr destroyed FIRST. Stack destruction is reverse of declaration:
  // endpoint -> http -> server — the safe order.
  JsonRpcServer server;
  server.registerMethod("block",
                        [&](const Json &, RpcContext &ctx) -> Json
                        {
                          observedSubject = ctx.authSubject().value_or("");
                          handlerEntered.store(true, std::memory_order_release);
                          std::unique_lock<std::mutex> lk(m);
                          cv.wait(lk, [&] { return release; });
                          handlerOrder.store(++seq, std::memory_order_seq_cst);
                          Json r;
                          r["done"] = true;
                          return r;
                        });

  const std::uint16_t port = testnet::getFreePortTCP();
  iora::network::HttpServer http("127.0.0.1", static_cast<int>(port));

  JsonRpcHttpOptions ho;
  ho.requireAuth = true;
  ho.tokenValidator = [tokens](std::string_view token) -> std::optional<std::string>
  {
    auto it = tokens->find(std::string(token));
    if (it == tokens->end())
    {
      return std::nullopt;
    }
    return it->second;
  };
  auto endpoint = std::make_unique<JsonRpcHttpEndpoint>(server, http, ho);
  http.start();

  iora::core::ThreadPool pool(2, 4, 2s);
  JsonRpcClient client(pool, e2eConfig());
  const std::string url = "http://localhost:" + std::to_string(port) + "/rpc";
  const std::vector<std::pair<std::string, std::string>> authHeaders{
    {"Authorization", "Bearer " + kToken}};

  // RAII backstop: guarantees each worker thread is joined even if a statement
  // between construction and the explicit joins below (e.g. http.stop()) were to
  // throw — a std::thread destroyed while joinable would std::terminate. The
  // explicit joins run first on the normal path; these then see non-joinable.
  struct ThreadJoiner
  {
    std::thread &t;
    ~ThreadJoiner()
    {
      if (t.joinable())
      {
        t.join();
      }
    }
  };

  // Issue the call on another thread; the handler blocks it in-flight. The
  // return value is intentionally discarded — this case proves drain ORDERING
  // and teardown safety, not response delivery (the socket is closed by stop()).
  std::exception_ptr callErr;
  std::string callErrWhat;
  std::thread caller(
    [&]
    {
      try
      {
        client.call(url, "block", Json("go"), authHeaders);
      }
      catch (const std::exception &e)
      {
        callErr = std::current_exception();
        callErrWhat = e.what();
      }
      catch (...)
      {
        callErr = std::current_exception();
        callErrWhat = "<non-std::exception>";
      }
    });
  ThreadJoiner joinCaller{caller};

  // Wait (bounded) until the dispatch is genuinely IN-FLIGHT (handler running)
  // before we stop() — this is what makes the drain non-vacuous. On timeout
  // (a wiring/auth regression that never reaches the handler) we record the miss
  // and still run the release + stop + join path below so the test never hangs,
  // then FAIL diagnosably at the assertions (once both threads are joined).
  bool handlerDidEnter = false;
  {
    const auto entryDeadline = std::chrono::steady_clock::now() + 5s;
    while (std::chrono::steady_clock::now() < entryDeadline)
    {
      if (handlerEntered.load(std::memory_order_acquire))
      {
        handlerDidEnter = true;
        break;
      }
      std::this_thread::sleep_for(1ms);
    }
  }

  // Release the handler only after stop() has had time to enter its drain wait.
  const auto kHold = 300ms;
  std::thread releaser(
    [&]
    {
      std::this_thread::sleep_for(kHold);
      {
        std::lock_guard<std::mutex> lk(m);
        release = true;
      }
      cv.notify_all();
    });
  ThreadJoiner joinReleaser{releaser};

  const auto t0 = std::chrono::steady_clock::now();
  http.stop(); // MUST block until the in-flight handler completes and drains
  const auto stopDuration = std::chrono::steady_clock::now() - t0;
  const int stopOrder = ++seq;

  caller.join();
  releaser.join();

  // What HttpServer::stop() guarantees for an in-flight dispatch (and what
  // task-8.1 asks this case to prove) is that the handler finishes EXECUTING
  // before stop() returns — so teardown never races a live handler — NOT that
  // the response is delivered. stop() closes the transport (and the in-flight
  // session) after a 50 ms grace, then drains; a handler held past that grace
  // completes, but its reply travels over an already-closed socket, so the
  // client observes a connection close. That the migrated client then does NOT
  // auto-retry the non-idempotent call (RFC 9110 §9.2.2) is the correct outcome.
  UNSCOPED_INFO("client call terminal state: "
                << (callErr ? ("error: " + callErrWhat) : "result delivered")
                << "; stopDuration(ms)="
                << std::chrono::duration_cast<std::chrono::milliseconds>(stopDuration).count());

  // The dispatch actually reached the handler and was in-flight when we stopped;
  // otherwise the whole case is vacuous. Asserted here (after both joins) so a
  // miss FAILs diagnosably rather than hanging.
  REQUIRE(handlerDidEnter);

  // M4: the stateful validator ran with its captured token store still alive for
  // the in-flight dispatch (observedSubject is set at handler entry, before the
  // block), proving the captured state outlived the request held across stop().
  REQUIRE(observedSubject == kSubject);

  // THE point of the case (M1): stop() returned ONLY AFTER the handler completed.
  // The cross-thread ordering is established by http.stop() joining the handler
  // thread (a happens-before edge), NOT by the atomics' memory order — seq_cst
  // here is merely conservative and the counters exist for data-race freedom.
  // This is a sequence check, not a timing window: not satisfiable by an
  // idle-queue drain and not by raising a timeout.
  REQUIRE(handlerOrder.load() > 0);
  REQUIRE(handlerOrder.load() < stopOrder);

  // stop() genuinely WAITED for the ~300 ms hold — well past its 50 ms grace,
  // proving the drain was non-vacuous. A lower bound only; the sequence
  // assertion above is the definitive proof.
  REQUIRE(stopDuration >= 150ms);

  // The call terminated deterministically (caller.join() returned). retriedRequests
  // is 0 here because e2eConfig() sets maxRetries=0, so this asserts the config
  // path, not the RFC 9110 §9.2.2 not-sent gate — that gate is exercised
  // end-to-end in the client retry-safety tests (iora_test_jsonrpc_client.cpp).
  REQUIRE(client.getStats().retriedRequests == 0);

  // Safe teardown order (D-LIFETIME): endpoint destroyed FIRST, explicitly,
  // while server + http are still alive; stop() already completed above. http
  // and server then destruct in reverse declaration order at scope exit. Under
  // ASan/TSan (task-10.2) this proves the drain leaves teardown UAF-free.
  endpoint.reset();
}
