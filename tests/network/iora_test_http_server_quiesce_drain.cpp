// Tests for HttpServer::quiesceTransport() drain semantics (tracker 2026-09-11-22).
//
// The fix replaces the old 2s hard drain cap (which abandoned live pool workers
// -> residual use-after-free of derived members) with an UNBOUNDED drain to
// getInFlightCount()==0, guarded by a fatal-abort circuit breaker at
// drainDeadline() (default 30s). Coverage:
//   * REGRESSION  - a handler that runs past the OLD 2s cap but finishes: quiesce
//                   MUST wait for it (not abandon), proving the 2s abandon is gone.
//   * HAPPY PATH  - fast handler drains in ms; idempotent second stop.
//   * CIRCUIT     - a wedged handler + a shrunk drainDeadline() must abort the
//                   process (SIGABRT), verified via a fork() child (constructed
//                   post-fork so the pool/workers exist in the aborting process).
//   * PREDICATE   - correct-by-construction: quiesceTransport() drains on the
//                   pool's single-critical-section getInFlightCount(), whose
//                   pop->++_busyThreads-atomic-with-the-pop closes the TOCTOU the
//                   two-sample getPendingTaskCount()/getActiveThreadCount() left
//                   open. The busy-but-not-active window is only reachable through
//                   ThreadPoolT<true>'s test seam (compiled out of the production
//                   ThreadPoolT<false> HttpServer holds), so it is asserted by
//                   pool-level seam tests + code review, not an HttpServer race
//                   test that cannot exist (see tracker).
#define CATCH_CONFIG_MAIN
#include "iora_test_net_utils.hpp"
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

using namespace iora::test;

TEST_CASE("HttpServer quiesce waits for an in-flight handler instead of abandoning at 2s")
{
  const std::uint16_t port = testnet::getFreePortTCP();
  iora::network::WebhookServer server;
  server.setPort(static_cast<int>(port));

  std::atomic<bool> started{false};
  std::atomic<bool> completed{false};

  // Plain onGet handler (per tracker R2-5a) that runs ~2.5s -- longer than the OLD
  // 2s drain cap. quiesce must wait for it: the old cap would `break` at ~2s with
  // `completed` still false and a worker still dereferencing server/handler state.
  server.onGet("/slow",
               [&](const iora::network::WebhookServer::Request &,
                   iora::network::WebhookServer::Response &res)
               {
                 started.store(true);
                 std::this_thread::sleep_for(std::chrono::milliseconds(2500));
                 completed.store(true);
                 res.set_content("done", "text/plain");
               });

  server.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  // The response only arrives after the 2.5s handler, so issue it off-thread.
  std::thread reqThread(
    [port]
    {
      iora::network::HttpClient client;
      try
      {
        client.get("http://127.0.0.1:" + std::to_string(port) + "/slow");
      }
      catch (...)
      {
      }
    });

  // Wait until the handler is actually executing on a worker (in-flight).
  REQUIRE(waitFor([&] { return started.load(); }, std::chrono::seconds(5)));
  REQUIRE_FALSE(completed.load());

  const auto t0 = std::chrono::steady_clock::now();
  server.stop(); // must WAIT for the in-flight handler, not abandon at 2s
  const auto elapsed = std::chrono::steady_clock::now() - t0;

  // Discriminators vs. the old 2s-cap behaviour: it would have returned at ~2s
  // with completed == false. The unbounded drain returns only once the ~2.5s
  // handler has finished.
  REQUIRE(completed.load());
  REQUIRE(elapsed >= std::chrono::milliseconds(2200));

  reqThread.join();
}

TEST_CASE("HttpServer quiesce drains fast handlers quickly and is idempotent")
{
  const std::uint16_t port = testnet::getFreePortTCP();
  iora::network::WebhookServer server;
  server.setPort(static_cast<int>(port));

  std::atomic<int> hits{0};
  server.onGet("/fast",
               [&](const iora::network::WebhookServer::Request &,
                   iora::network::WebhookServer::Response &res)
               {
                 hits.fetch_add(1);
                 res.set_content("ok", "text/plain");
               });

  server.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(100));

  {
    iora::network::HttpClient client;
    auto res = client.get("http://127.0.0.1:" + std::to_string(port) + "/fast");
    REQUIRE(res.success());
  }

  const auto t0 = std::chrono::steady_clock::now();
  server.stop(); // no in-flight work -> getInFlightCount()==0 -> drains in ms
  const auto elapsed = std::chrono::steady_clock::now() - t0;

  REQUIRE(hits.load() == 1);
  REQUIRE(elapsed < std::chrono::seconds(2));

  // Idempotent: second stop() early-outs on the null _transport.
  REQUIRE_NOTHROW(server.stop());
}

// CIRCUIT BREAKER: a handler that ignores getShutdownChecker() and never returns
// must, past drainDeadline(), abort the process rather than abandon the drain
// (UAF) or hang forever. Verified in a fork() child so the SIGABRT is contained
// and asserted by the parent. Everything (server + pool + wedged worker) is
// constructed POST-FORK: only the calling thread survives fork(), so a pre-fork
// pool would have no workers in the child (tracker M-b / R2-3).
TEST_CASE("HttpServer quiesce aborts the process when a handler wedges past the deadline")
{
  const pid_t pid = fork();
  REQUIRE(pid >= 0);

  if (pid == 0)
  {
    // ---- CHILD ---- (never uses Catch2; exits via abort() or a distinct _Exit()).
    // Watchdog: if the abort never fires, SIGALRM kills us so the parent sees a
    // signal != SIGABRT and the test fails loudly instead of hanging to TIMEOUT.
    alarm(15);

    struct FastDeadlineServer : iora::network::WebhookServer
    {
      std::chrono::milliseconds drainDeadline() const override
      {
        return std::chrono::milliseconds(300);
      }
    };

    std::atomic<bool> inHandler{false};
    FastDeadlineServer *server = nullptr;

    // Wrap ALL setup so the ONLY path to SIGABRT is stop()'s deadline abort: an
    // uncaught exception here (e.g. start() bind failure) would otherwise become
    // std::terminate -> SIGABRT and pass the parent's assertion for the wrong
    // reason (tracker code-review M-1). _Exit(44) disambiguates that.
    try
    {
      const std::uint16_t port = testnet::getFreePortTCP();
      server = new FastDeadlineServer(); // leaked deliberately; the child aborts
      server->setPort(static_cast<int>(port));
      server->onGet("/wedge",
                    [&](const iora::network::WebhookServer::Request &,
                        iora::network::WebhookServer::Response &)
                    {
                      inHandler.store(true);
                      for (;;) // wedge forever, ignoring getShutdownChecker()
                      {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                      }
                    });
      server->start();
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

      std::thread reqThread(
        [port]
        {
          iora::network::HttpClient client;
          try
          {
            client.get("http://127.0.0.1:" + std::to_string(port) + "/wedge");
          }
          catch (...)
          {
          }
        });
      reqThread.detach();

      // Establish the observable in-flight precondition BEFORE stop() (tracker
      // R2-3): otherwise the drain would find getInFlightCount()==0, return
      // instantly, and the SIGABRT assertion would be vacuous.
      if (!waitFor([&] { return inHandler.load(); }, std::chrono::seconds(5)))
      {
        std::_Exit(42); // handler never ran -> would be vacuous; fail explicitly
      }
    }
    catch (...)
    {
      std::_Exit(44); // setup threw -> a SIGABRT here would be for the wrong reason
    }

    server->stop(); // EXPECTED: std::abort() at the 300ms deadline
    std::_Exit(43); // reached only if stop() returned without aborting -> fail
  }

  // ---- PARENT ----
  int status = 0;
  REQUIRE(waitpid(pid, &status, 0) == pid);
  REQUIRE(WIFSIGNALED(status));
  REQUIRE(WTERMSIG(status) == SIGABRT);
}
