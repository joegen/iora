// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file iora_test_dns_transport_retry.cpp
/// \brief Retry-path regression tests for DnsTransport (tracker 2026-09-24-31).
///
/// The P0 this pins: scheduleQueryTimeout used to FAIL a query at the first timeout, so the
/// retryCount/initialRetryDelay/retryMultiplier/jitterFactor policy was inert -- every query
/// was sent exactly once. The fix makes the per-query timeout timer the SOLE retry driver:
/// on expiry it CLAIMS a retransmission (attempt-limit check + retryCount increment + startTime
/// reset + retryClaimed) as ONE critical section under _queriesMutex, then re-sends to the SAME
/// server (same query id -- required for late-answer correlation) after exponential backoff,
/// and fails with a terminal DnsTimeoutException only after the last attempt. The 10 s cleanup
/// sweep is demoted to a strict orphan BACKSTOP that never retries.
///
/// SCOPE (human decision 2026-09-24): SAME-SERVER retransmission only. Cross-server per-query
/// FAILOVER stays a documented dns_client.md limitation and is NOT exercised here.
///
/// TEST STRATEGY (test_plan recipe):
///   - Real-I/O KATs use a locally-bound loopback UDP socket (UdpProbe) that records the arrival
///     time of every datagram the client sends and, per policy, stays silent (drives real
///     timeouts/retries) or answers (drives success/late/duplicate correlation). Ephemeral port
///     (bind :0 + getsockname) avoids the port-probe TOCTOU entirely. jitterFactor=0 and short
///     timeout/backoff make the datagram COUNT deterministic; timer delays are wall-clock, so the
///     inter-datagram GAP ordering is robust even under TSan (only the tiny per-attempt processing
///     overhead is CPU-bound, not the configured sleeps).
///   - The retry-vs-TCP-fallback arbitration (retryClaimed drop-and-wait) is driven WHITE-BOX via
///     the DnsTransportTestAccess seam -- firing a real UDP timeout concurrently with a truncated
///     datagram is a race a socket test cannot make deterministic; the seam pins the arbitration
///     flag's effect in processResponse directly, and the sole-driver/orphan-backstop sweep
///     semantics are pinned here (and in iora_test_dns_transport_callback_deadlock's F-4b).
///
/// Every ctest invocation MUST carry --timeout (a genuine retry-path hang must fail, never wedge).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "dns_transport_test_access.hpp"    // shared white-box seam (SM-M1)

#include "iora/network/dns/dns_message.hpp"
#include "iora/network/dns/dns_types.hpp"
#include "iora/network/transport_types.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace iora::network::dns;
using iora::network::SessionId;
using Access = iora::network::dns::DnsTransportTestAccess;
using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

namespace
{

// ---------------------------------------------------------------------------------------------
// UdpProbe: a loopback UDP endpoint that records the arrival time of every datagram the client
// sends it and, per policy, either stays SILENT (never answers -> drives real timeouts/retries)
// or answers (drives response correlation). No real network; ephemeral port; single receive
// thread. Delayed answers are dispatched on detached threads so a delay never blocks the receive
// loop (which must keep recording later retransmissions).
// ---------------------------------------------------------------------------------------------
class UdpProbe
{
public:
  struct Policy
  {
    // 0 => never answer (silent forever). N>=1 => consider answering from the Nth datagram on.
    int answerFromCount{0};
    // If true, answer ONLY the single datagram whose index == answerFromCount (used to make a
    // delayed answer to attempt 1 land AFTER a later retransmission has already gone out).
    bool answerExactlyOne{false};
    int duplicateAnswers{1};      // identical answer datagrams to emit per triggering datagram
    bool truncate{false};         // set TC=1 in the answer (UDP truncation)
    bool bogusId{false};          // answer with a mismatched id -> client must ignore it
    bool unparseable{false};      // reply with a matching id but a body DnsMessage::parse rejects
    int rcode{0};                 // response rcode (0=NOERROR w/ 1 A answer; 3=NXDOMAIN, 0 answers)
    milliseconds answerDelay{0};  // delay before emitting the answer(s)
  };

  ~UdpProbe() { stop(); }

  bool start()
  {
    sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ < 0)
    {
      return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // ephemeral -> race-free (no port-probe TOCTOU)
    if (::bind(sock_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
      ::close(sock_);
      sock_ = -1;
      return false;
    }
    socklen_t len = sizeof(addr);
    if (::getsockname(sock_, reinterpret_cast<sockaddr *>(&addr), &len) < 0)
    {
      ::close(sock_);
      sock_ = -1;
      return false;
    }
    port_ = ntohs(addr.sin_port);
    running_.store(true);
    thread_ = std::thread([this]() { loop(); });
    return true;
  }

  void stop()
  {
    if (running_.exchange(false))
    {
      int fd = sock_.load();
      // Close the fd UNDER m_ (LOW-1): a delayed-answer sender does its sock_ load + sendto while
      // holding m_ too, so a send can never straddle the close onto a closed/reused fd (the earlier
      // re-read alone left a nanosecond TOCTOU). shutdown()+close() still wakes the blocked recvfrom
      // (the recv loop does not hold m_ while in recvfrom).
      {
        std::lock_guard<std::mutex> l(m_);
        if (fd >= 0)
        {
          ::shutdown(fd, SHUT_RDWR); // wake a blocked recvfrom
          ::close(fd);
          sock_.store(-1);
        }
      }
      if (thread_.joinable())
      {
        thread_.join(); // recv loop is done -> no more answer threads will be spawned
      }
      // Join delayed-answer senders (T-L1): bounds their lifetime to the probe's (they capture
      // `this`), so none outlives ~UdpProbe.
      for (auto &at : answerThreads_)
      {
        if (at.joinable())
        {
          at.join();
        }
      }
      answerThreads_.clear();
    }
  }

  void setPolicy(const Policy &p)
  {
    std::lock_guard<std::mutex> l(m_);
    policy_ = p;
  }

  std::uint16_t port() const { return port_; }
  int count() const { return count_.load(); }

  std::vector<Clock::time_point> times() const
  {
    std::lock_guard<std::mutex> l(m_);
    return times_;
  }

  // Inter-datagram gaps in milliseconds (times[i+1] - times[i]).
  std::vector<long> gapsMs() const
  {
    auto t = times();
    std::vector<long> g;
    for (std::size_t i = 1; i < t.size(); ++i)
    {
      g.push_back(std::chrono::duration_cast<milliseconds>(t[i] - t[i - 1]).count());
    }
    return g;
  }

private:
  void loop()
  {
    std::vector<std::uint8_t> buf(4096);
    sockaddr_in from{};
    socklen_t fromLen = sizeof(from);
    while (running_.load())
    {
      ssize_t n = ::recvfrom(sock_.load(), buf.data(), buf.size(), 0,
                             reinterpret_cast<sockaddr *>(&from), &fromLen);
      if (n < 0)
      {
        if (!running_.load())
        {
          break;
        }
        continue;
      }
      auto now = Clock::now();
      Policy pol;
      int c;
      {
        std::lock_guard<std::mutex> l(m_);
        times_.push_back(now);
        pol = policy_;
      }
      c = ++count_;

      if (pol.answerFromCount == 0)
      {
        continue; // silent
      }
      bool shouldAnswer = pol.answerExactlyOne ? (c == pol.answerFromCount)
                                               : (c >= pol.answerFromCount);
      if (!shouldAnswer)
      {
        continue;
      }

      auto resp = pol.unparseable
                    ? unparseableResponse(buf.data(), static_cast<std::size_t>(n))
                    : buildResponse(buf.data(), static_cast<std::size_t>(n), pol.truncate,
                                    pol.bogusId, pol.rcode);
      sockaddr_in dst = from;
      int dup = pol.duplicateAnswers;
      auto delay = pol.answerDelay;
      // Capture `this` (safe: every answer thread is joined in stop() BEFORE ~UdpProbe). Each send
      // reads sock_ and calls sendto UNDER m_ (T2R-3 / LOW-1), and stop() closes the fd under the same
      // m_, so a send can never straddle the close onto a closed/reused fd.
      auto send = [this, resp, dst, dup]()
      {
        for (int i = 0; i < dup; ++i)
        {
          std::lock_guard<std::mutex> l(m_);
          int fd = sock_.load();
          if (fd < 0)
          {
            break;
          }
          ::sendto(fd, resp.data(), resp.size(), 0,
                   reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));
        }
      };
      if (delay.count() > 0)
      {
        // Run on a separate thread so the delay does not stall the receive loop (later
        // retransmissions must still be recorded). `send` captures `this`; the thread is JOINED in
        // stop() (T-L1) before ~UdpProbe, so it never outlives the probe.
        answerThreads_.emplace_back(
          [send, delay]()
          {
            std::this_thread::sleep_for(delay);
            send();
          });
      }
      else
      {
        send();
      }
    }
  }

  // A datagram with the query's id in a valid 12-byte header (so it correlates to the pending
  // query) but a body DnsMessage::parse rejects: QDCOUNT=1 followed by a single label-length byte
  // (63) with no label bytes, so the question read overruns. Used to prove item K -- an unparseable
  // response that matches id+source must be DROPPED, never used to terminate the query.
  static std::vector<std::uint8_t> unparseableResponse(const std::uint8_t *q, std::size_t n)
  {
    std::vector<std::uint8_t> r(12, 0);
    if (n >= 2)
    {
      r[0] = q[0];
      r[1] = q[1]; // echo the id
    }
    r[2] = 0x81; // QR=1, RD=1
    r[3] = 0x80; // RA=1, rcode=0
    r[5] = 1;    // QDCOUNT=1 -> a question is expected ...
    r.push_back(0x3F); // ... but only a bare label-length byte (63) follows -> parse overruns
    return r;
  }

  // Build a minimal DNS response echoing the query's question section. NOERROR (rcode 0, not
  // truncated) carries one A answer; \p truncate sets TC=1 with 0 answers (drives UDP->TCP
  // fallback); \p rcode != 0 (e.g. 3 = NXDOMAIN) is a definitive negative answer with 0 answers;
  // \p bogusId flips the id so the client cannot correlate it (must be ignored).
  static std::vector<std::uint8_t> buildResponse(const std::uint8_t *q, std::size_t n,
                                                 bool truncate, bool bogusId, int rcode = 0)
  {
    std::vector<std::uint8_t> r;
    if (n < 12)
    {
      return r;
    }
    // Locate end of the question (labels .. 0x00, then QTYPE(2) + QCLASS(2)).
    std::size_t pos = 12;
    while (pos < n && q[pos] != 0)
    {
      pos += 1 + q[pos];
    }
    if (pos >= n)
    {
      return r;
    }
    ++pos;         // past the 0x00 label terminator
    pos += 4;      // QTYPE + QCLASS
    if (pos > n)
    {
      return r;
    }
    std::size_t qEnd = pos;

    r.resize(12);
    std::uint16_t id = static_cast<std::uint16_t>((q[0] << 8) | q[1]);
    if (bogusId)
    {
      id ^= 0xFFFF;
    }
    bool hasAnswer = !truncate && rcode == 0;
    r[0] = static_cast<std::uint8_t>(id >> 8);
    r[1] = static_cast<std::uint8_t>(id & 0xFF);
    r[2] = static_cast<std::uint8_t>(0x81 | (truncate ? 0x02 : 0x00)); // QR=1, RD=1 [, TC=1]
    r[3] = static_cast<std::uint8_t>(0x80 | (rcode & 0x0F));           // RA=1, rcode
    r[4] = 0;
    r[5] = 1;                                    // QDCOUNT=1
    r[6] = 0;
    r[7] = static_cast<std::uint8_t>(hasAnswer ? 1 : 0); // ANCOUNT (0 when truncated or rcode!=0)
    r[8] = r[9] = r[10] = r[11] = 0;             // NS/AR counts = 0

    // Echo the question section verbatim.
    r.insert(r.end(), q + 12, q + qEnd);

    if (hasAnswer)
    {
      // One A answer using a compression pointer to the question name (offset 12).
      r.push_back(0xC0);
      r.push_back(0x0C);
      r.push_back(0x00);
      r.push_back(0x01); // TYPE=A
      r.push_back(0x00);
      r.push_back(0x01); // CLASS=IN
      r.push_back(0x00);
      r.push_back(0x00);
      r.push_back(0x00);
      r.push_back(0x3C); // TTL=60
      r.push_back(0x00);
      r.push_back(0x04); // RDLENGTH=4
      r.push_back(1);
      r.push_back(2);
      r.push_back(3);
      r.push_back(4); // 1.2.3.4
    }
    return r;
  }

  std::atomic<int> sock_{-1};   // atomic (T-M2): read in loop() concurrently with stop()'s reset
  std::uint16_t port_{0};
  std::atomic<bool> running_{false};
  std::atomic<int> count_{0};
  std::thread thread_;
  mutable std::mutex m_;
  std::vector<Clock::time_point> times_;
  std::vector<std::thread> answerThreads_; // delayed-answer senders, joined in stop() (T-L1)
  Policy policy_;
};

// Build a DnsConfig pointing exclusively at the loopback probe, with a deterministic retry
// policy (jitterFactor=0 unless overridden by the caller).
DnsConfig probeConfig(std::uint16_t port, int retryCount, milliseconds timeout,
                      milliseconds initialRetryDelay, double multiplier = 2.0,
                      double jitterFactor = 0.0,
                      DnsTransportMode mode = DnsTransportMode::UDP)
{
  DnsConfig cfg;
  cfg.servers = {DnsServer("127.0.0.1", port)};
  cfg.timeout = timeout;
  cfg.retryCount = retryCount;
  cfg.initialRetryDelay = initialRetryDelay;
  cfg.retryMultiplier = multiplier;
  cfg.maxRetryDelay = milliseconds(60000);
  cfg.jitterFactor = jitterFactor;
  cfg.transportMode = mode;
  cfg.enableCache = false;
  return cfg;
}

// One query issued against the probe. Collects the single completion (result or error) and how
// many times the callback fired (a second firing is a defect, never masked).
struct QueryOutcome
{
  std::atomic<int> callbacks{0};
  std::atomic<bool> success{false};
  std::atomic<bool> error{false};
  std::atomic<bool> timeoutError{false};
  std::promise<void> firstDone;
};

void issueQuery(const std::shared_ptr<DnsTransport> &t, std::uint16_t port, QueryOutcome &out)
{
  t->queryAsync(
    DnsQuestion("retry.test", DnsType::A, DnsClass::IN),
    [&out](const DnsResult &, const std::exception_ptr &err)
    {
      int n = ++out.callbacks;
      if (err)
      {
        out.error.store(true);
        try
        {
          std::rethrow_exception(err);
        }
        catch (const DnsTimeoutException &)
        {
          out.timeoutError.store(true);
        }
        catch (...)
        {
        }
      }
      else
      {
        out.success.store(true);
      }
      if (n == 1)
      {
        out.firstDone.set_value();
      }
    },
    "127.0.0.1", port);
}

bool waitFor(std::future<void> &f, milliseconds budget)
{
  return f.wait_for(budget) == std::future_status::ready;
}

// White-box: a makeshift truncated UDP response for the arbitration KAT (QR=1, TC=1).
std::vector<std::uint8_t> truncatedResponse(std::uint16_t id)
{
  auto q = DnsMessage::buildQuery(DnsQuestion("retry.test", DnsType::A, DnsClass::IN), id);
  // Flip to a response and set the TC bit (byte 2: QR=0x80, TC=0x02).
  q[2] = static_cast<std::uint8_t>(q[2] | 0x80 | 0x02);
  return q;
}

constexpr const char *LOOP = "127.0.0.1";

} // namespace

// =============================================================================================
// KAT 1: silent server -> exactly retryCount+1 datagrams to the SAME server, monotonically
// increasing inter-send gaps (backoff), ONE terminal DnsTimeoutException, callback fired once.
// =============================================================================================
TEST_CASE("dns retry: silent server sends retryCount+1 datagrams then one terminal timeout",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  probe.setPolicy({}); // silent

  const int retryCount = 2;
  auto cfg = probeConfig(probe.port(), retryCount, milliseconds(250), milliseconds(150));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(4000)));
  // Grace window: catch any erroneous extra datagram or double-callback.
  std::this_thread::sleep_for(milliseconds(400));

  CHECK(out.callbacks.load() == 1);
  CHECK(out.error.load());
  CHECK(out.timeoutError.load());
  CHECK_FALSE(out.success.load());

  // retryCount+1 attempts, all to the SAME server (the probe is the only endpoint).
  CHECK(probe.count() == retryCount + 1);

  auto gaps = probe.gapsMs();
  REQUIRE(gaps.size() == static_cast<std::size_t>(retryCount));
  // Each attempt waited ~timeout before the retry was even claimed (per-attempt timeout).
  for (long g : gaps)
  {
    CHECK(g >= 200); // timeout 250ms minus scheduling slack
  }
  // Backoff grew (delay tier 0 = 150ms, tier 1 = 300ms -> gaps 400ms, 550ms).
  CHECK(gaps[1] > gaps[0]);

  auto stats = t->getStatistics();
  CHECK(stats.retries == static_cast<std::uint64_t>(retryCount)); // one per resend
  CHECK(stats.timeouts == 1);                                     // terminal timeout only
  // A terminal timeout is counted ONLY as a timeout, never also as an error (item H / C-M1): the
  // timeout callback's terminal branch (scheduleQueryTimeout) fails via takePending+failOne, not
  // completeQuery (which would bump errors).
  CHECK(stats.errors == 0);

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 1b (H-1 regression): transportMode == Both (the DEFAULT config) must ALSO retransmit. The
// initial send treats Both as UDP-first, so a silent server must produce retryCount+1 UDP datagrams
// and a terminal timeout -- NOT strand the query (the pre-fix resend dispatch sent nothing for Both,
// leaving retries inert for the default mode and hanging async queries forever).
// =============================================================================================
TEST_CASE("dns retry: Both (default) transport mode retransmits over UDP on a silent server",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  probe.setPolicy({}); // silent

  const int retryCount = 2;
  auto cfg = probeConfig(probe.port(), retryCount, milliseconds(250), milliseconds(150),
                         /*mult=*/2.0, /*jitter=*/0.0, DnsTransportMode::Both);
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(4000)));
  std::this_thread::sleep_for(milliseconds(400));

  CHECK(out.callbacks.load() == 1);
  CHECK(out.timeoutError.load());           // it terminates (does not strand)
  CHECK(probe.count() == retryCount + 1);   // Both retransmits over UDP: full attempt budget spent
  CHECK(t->getStatistics().retries == static_cast<std::uint64_t>(retryCount));

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 2: success after one retry -> single success, retryCount==1, no orphaned resend, no
// double-callback.
// =============================================================================================
TEST_CASE("dns retry: answer on the second attempt completes once with a single retry",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  UdpProbe::Policy pol;
  pol.answerFromCount = 2; // silent on attempt 1, answer attempt 2 (and any later)
  probe.setPolicy(pol);

  auto cfg = probeConfig(probe.port(), /*retryCount=*/3, milliseconds(250), milliseconds(120));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(4000)));
  std::this_thread::sleep_for(milliseconds(400));

  CHECK(out.callbacks.load() == 1);
  CHECK(out.success.load());
  CHECK_FALSE(out.error.load());
  // Exactly two datagrams: the silent first + the answered retry. No orphaned third attempt.
  CHECK(probe.count() == 2);

  auto stats = t->getStatistics();
  CHECK(stats.retries == 1);

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 3 + 4: per-attempt timeout accounting and deterministic backoff growth (jitterFactor=0).
// =============================================================================================
TEST_CASE("dns retry: per-attempt timeout and deterministic exponential backoff growth",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  probe.setPolicy({}); // silent

  const int retryCount = 3;
  const milliseconds timeout(200);
  const milliseconds initial(100);
  const double mult = 2.0;
  auto cfg = probeConfig(probe.port(), retryCount, timeout, initial, mult, /*jitter=*/0.0);
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(5000)));
  std::this_thread::sleep_for(milliseconds(300));

  CHECK(probe.count() == retryCount + 1);
  auto gaps = probe.gapsMs();
  REQUIRE(gaps.size() == static_cast<std::size_t>(retryCount));

  // Expected gap_n = timeout + initial*mult^n : 300, 400, 600ms. Assert per-attempt timeout was
  // spent (gap >= ~timeout) and each gap is strictly larger than the previous (backoff grows).
  long prev = 0;
  double baseDelay = static_cast<double>(initial.count());
  for (std::size_t n = 0; n < gaps.size(); ++n)
  {
    long expected = timeout.count() + static_cast<long>(baseDelay);
    CHECK(gaps[n] >= timeout.count() - 40);      // per-attempt timeout was waited
    CHECK(gaps[n] >= expected - 80);             // >= timeout + this tier's backoff (lower bound)
    if (n > 0)
    {
      CHECK(gaps[n] > prev);                      // monotonic growth
    }
    prev = gaps[n];
    baseDelay *= mult;
  }

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 4b: jitter stays within [base*(1-f), base*(1+f)] (bounded, non-deterministic).
// =============================================================================================
TEST_CASE("dns retry: jittered backoff stays within the configured bounds", "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  probe.setPolicy({}); // silent

  const int retryCount = 3;
  const milliseconds timeout(200);
  const milliseconds initial(200);
  const double mult = 2.0;
  const double jitter = 0.25;
  auto cfg = probeConfig(probe.port(), retryCount, timeout, initial, mult, jitter);
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(6000)));
  std::this_thread::sleep_for(milliseconds(300));

  CHECK(probe.count() == retryCount + 1);
  auto gaps = probe.gapsMs();
  REQUIRE(gaps.size() == static_cast<std::size_t>(retryCount));

  double baseDelay = static_cast<double>(initial.count());
  for (std::size_t n = 0; n < gaps.size(); ++n)
  {
    long lo = timeout.count() + static_cast<long>(baseDelay * (1.0 - jitter)) - 80;
    long hi = timeout.count() + static_cast<long>(baseDelay * (1.0 + jitter)) + 250; // sched slack
    CHECK(gaps[n] >= lo);
    CHECK(gaps[n] <= hi);
    baseDelay *= mult;
  }

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 5: retryCount==0 -> exactly one datagram, immediate terminal failure.
// =============================================================================================
TEST_CASE("dns retry: retryCount==0 sends exactly one datagram and fails immediately",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  probe.setPolicy({}); // silent

  auto cfg = probeConfig(probe.port(), /*retryCount=*/0, milliseconds(200), milliseconds(100));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  auto t0 = Clock::now();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(2000)));
  auto elapsed = std::chrono::duration_cast<milliseconds>(Clock::now() - t0).count();
  std::this_thread::sleep_for(milliseconds(300));

  CHECK(out.callbacks.load() == 1);
  CHECK(out.timeoutError.load());
  CHECK(probe.count() == 1); // no retry attempted
  // Terminal at ~timeout (no backoff, no extra attempt).
  CHECK(elapsed < 1000);

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 7: total wall-time for an all-silent query is bounded by calculateMaxSyncWaitTime().
// =============================================================================================
TEST_CASE("dns retry: total latency is bounded by the computed sync-wait budget", "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  probe.setPolicy({}); // silent

  auto cfg = probeConfig(probe.port(), /*retryCount=*/2, milliseconds(200), milliseconds(150));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  auto t0 = Clock::now();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(5000)));
  auto elapsed = std::chrono::duration_cast<milliseconds>(Clock::now() - t0).count();

  // calculateMaxSyncWaitTime() = timeout + sum(backoff tiers) + jitter + margin. The async terminal
  // must land within that same budget (it is what the sync path's wait_for uses). Assert against the
  // transport's OWN computed budget via the seam (C-L2) rather than re-deriving the formula here,
  // which would silently drift if the formula changes.
  long expectedBudget = Access::calcMaxSyncWait(*t).count();
  CHECK(elapsed <= expectedBudget);
  CHECK(out.timeoutError.load());

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 8: stop() during a backoff window drains the pending query (promise set, no resend after
// stop, no orphaned timer, no UAF -- the last is a TSan property).
// =============================================================================================
TEST_CASE("dns retry: stop() during backoff drains the query with no post-stop resend",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  probe.setPolicy({}); // silent

  auto cfg = probeConfig(probe.port(), /*retryCount=*/5, milliseconds(200), milliseconds(300));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  // Enter the inter-attempt BACKOFF window (C-M4): with timeout=200 ms and initialRetryDelay=300 ms,
  // the first datagram goes out at ~t0, its timeout fires at ~t0+200 (claiming a retry), and the
  // backoff resend is scheduled for ~t0+500. Sleeping ~300 ms after the first datagram lands us at
  // ~t0+300 -- the retry is CLAIMED and an armed backoff resend timer is pending, but the resend has
  // NOT gone out yet. That is precisely the state this KAT must drain (the old 50 ms sleep sat in the
  // first timeout window, before any retry was claimed).
  auto deadline = Clock::now() + milliseconds(1500);
  while (probe.count() < 1 && Clock::now() < deadline)
  {
    std::this_thread::sleep_for(milliseconds(10));
  }
  REQUIRE(probe.count() == 1);
  std::this_thread::sleep_for(milliseconds(300)); // past the 200 ms timeout, before the 500 ms resend
  REQUIRE(probe.count() == 1);                    // still in backoff: the resend has not fired yet

  t->stop(); // drains the mid-backoff pending query with a "Transport stopped" error

  REQUIRE(waitFor(fut, milliseconds(2000)));
  int countAtStop = probe.count();
  std::this_thread::sleep_for(milliseconds(500)); // no resend must arrive after stop()

  CHECK(out.callbacks.load() == 1);
  CHECK(out.error.load());
  CHECK(probe.count() == countAtStop); // no post-stop retransmission

  probe.stop();
}

// =============================================================================================
// KAT 9: a late answer to attempt 1 (delivered AFTER a retransmission already fired) still
// matches by id/server/port and completes the query exactly once.
// =============================================================================================
TEST_CASE("dns retry: a late answer arriving after a retry fired completes exactly once",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  UdpProbe::Policy pol;
  pol.answerFromCount = 1;
  pol.answerExactlyOne = true;               // answer ONLY attempt 1 ...
  pol.answerDelay = milliseconds(500);       // ... but late: after the retry has gone out
  probe.setPolicy(pol);

  // timeout 200 + backoff 150 => retry (attempt 2) at ~350ms; the delayed answer lands ~500ms.
  auto cfg = probeConfig(probe.port(), /*retryCount=*/3, milliseconds(200), milliseconds(150));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(4000)));
  std::this_thread::sleep_for(milliseconds(400));

  CHECK(out.callbacks.load() == 1);
  CHECK(out.success.load()); // the late answer still correlates and completes the query
  CHECK(probe.count() >= 2); // a retransmission had already fired -> the answer was genuinely late

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 10: a duplicate answer after completion is dropped harmlessly (one promise/callback).
// =============================================================================================
TEST_CASE("dns retry: a duplicate answer after completion is dropped, callback fires once",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  UdpProbe::Policy pol;
  pol.answerFromCount = 1;
  pol.duplicateAnswers = 3; // three identical answers to the first datagram
  probe.setPolicy(pol);

  auto cfg = probeConfig(probe.port(), /*retryCount=*/2, milliseconds(300), milliseconds(150));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(3000)));
  std::this_thread::sleep_for(milliseconds(400));

  CHECK(out.callbacks.load() == 1); // duplicates dropped
  CHECK(out.success.load());

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 10b (V-L3): a VALID answer arriving DURING the backoff window (after the timeout claimed a
// retry, before the resend goes out) completes the query and cancels the pending resend -- no extra
// datagram, single callback.
// =============================================================================================
TEST_CASE("dns retry: a valid answer during the backoff window completes and cancels the resend",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  UdpProbe::Policy pol;
  pol.answerFromCount = 1;
  pol.answerExactlyOne = true;         // answer attempt 1 only ...
  pol.answerDelay = milliseconds(300); // ... during the backoff: after the ~200ms timeout claim,
                                       //     before the ~200+300=500ms resend
  probe.setPolicy(pol);

  auto cfg = probeConfig(probe.port(), /*retryCount=*/3, milliseconds(200), milliseconds(300));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(4000)));
  std::this_thread::sleep_for(milliseconds(500)); // window in which a stray resend would have fired

  CHECK(out.callbacks.load() == 1);
  CHECK(out.success.load());
  CHECK(probe.count() == 1); // the pending backoff resend was cancelled by the completion

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 10c (V-L3): a definitive negative answer (NXDOMAIN) completes the query IMMEDIATELY with a
// single datagram -- a definitive rcode short-circuits retransmission (no retry budget consumed).
// =============================================================================================
TEST_CASE("dns retry: a definitive NXDOMAIN answer short-circuits retransmission", "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  UdpProbe::Policy pol;
  pol.answerFromCount = 1;
  pol.rcode = 3; // NXDOMAIN, 0 answers -- a definitive negative response
  probe.setPolicy(pol);

  auto cfg = probeConfig(probe.port(), /*retryCount=*/3, milliseconds(250), milliseconds(150));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(3000)));
  std::this_thread::sleep_for(milliseconds(400));

  CHECK(out.callbacks.load() == 1);
  CHECK(probe.count() == 1);            // definitive answer -> NO retransmission
  CHECK_FALSE(out.timeoutError.load()); // completed on the answer, not a timeout
  CHECK(t->getStatistics().retries == 0);

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 12: an ignored bogus datagram (mismatched id) does NOT complete the query and does NOT
// disturb the retry cadence -- the timeout/retry machinery is the sole thing advancing attempts.
// =============================================================================================
TEST_CASE("dns retry: a bogus-id datagram is ignored and does not consume a retry", "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  UdpProbe::Policy pol;
  pol.answerFromCount = 1;
  pol.answerExactlyOne = true; // reply to attempt 1 only ...
  pol.bogusId = true;          // ... with a mismatched id the client must ignore
  probe.setPolicy(pol);

  const int retryCount = 2;
  auto cfg = probeConfig(probe.port(), retryCount, milliseconds(250), milliseconds(150));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(4000)));
  std::this_thread::sleep_for(milliseconds(400));

  CHECK(out.callbacks.load() == 1);
  CHECK(out.timeoutError.load());        // bogus packet did NOT complete the query
  CHECK_FALSE(out.success.load());
  CHECK(probe.count() == retryCount + 1); // cadence undisturbed: full attempt budget still spent

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 12b (V-H1 / item K): an UNPARSEABLE datagram whose id+source MATCH the pending query must be
// dropped (drop-and-wait), NOT used to terminate the query. Pre-fix, the parse-failure branch
// completed the query with DnsParseException at the first attempt -- defeating retransmission and
// letting one crafted packet (the query id is reused across attempts) kill the query. Post-fix, the
// query ignores it, retransmits its full budget, and ends in a terminal DnsTimeoutException.
// =============================================================================================
TEST_CASE("dns retry: an unparseable matching-id datagram is dropped, not a query-killer",
          "[dns][retry]")
{
  UdpProbe probe;
  REQUIRE(probe.start());
  UdpProbe::Policy pol;
  pol.answerFromCount = 1;
  pol.answerExactlyOne = true; // send the malformed reply to attempt 1 only ...
  pol.unparseable = true;      // ... a matching-id datagram DnsMessage::parse rejects
  probe.setPolicy(pol);

  const int retryCount = 2;
  auto cfg = probeConfig(probe.port(), retryCount, milliseconds(250), milliseconds(150));
  auto t = std::make_shared<DnsTransport>(cfg);
  t->start();

  QueryOutcome out;
  auto fut = out.firstDone.get_future();
  issueQuery(t, probe.port(), out);

  REQUIRE(waitFor(fut, milliseconds(4000)));
  std::this_thread::sleep_for(milliseconds(400));

  CHECK(out.callbacks.load() == 1);
  CHECK(out.timeoutError.load());         // dropped, not terminated by the malformed packet
  CHECK_FALSE(out.success.load());
  CHECK(probe.count() == retryCount + 1); // full attempt budget still spent (retransmission survived)

  t->stop();
  probe.stop();
}

// =============================================================================================
// KAT 6 (white-box): the retry CLAIM closes the timer-vs-sweep double-claim window. The baseline
// sole-driver sweep semantics (healthy-with-live-timer is SKIPPED; a genuine orphan is FAILED) are
// owned by iora_test_dns_transport_callback_deadlock's F-4b and NOT re-asserted here (S-M2, dedup).
// This case pins ONLY the property unique to the retry claim: a query the claim has just mutated
// (retryCount incremented + startTime reset to now + a live backoff timer) is not-expired-by-
// startTime, so a sweep serialized right after the claim SKIPS it -- which is why the sole-driver
// design needs no CAS between the timeout timer and the sweep.
// =============================================================================================
TEST_CASE("dns retry: a racing sweep skips a query the retry claim just reset (no CAS needed)",
          "[dns][retry][whitebox]")
{
  constexpr std::uint16_t ID = 0x5151;
  constexpr std::uint16_t PORT = 5399;

  DnsConfig cfg;
  cfg.retryCount = 3;
  auto t = std::make_shared<DnsTransport>(cfg);
  // Model the EXACT window the "no CAS" argument relies on: after the claim releases _queriesMutex,
  // activeTimerId is briefly 0 (before retryQuery arms the backoff timer) AND startTime was just
  // reset. With activeTimerId == 0, ONLY the fresh startTime (not-expired) stops the orphan sweep
  // from failing the query. So register with activeTimerId == 0 (do NOT call setActiveTimerId) and a
  // fresh startTime under a long timeout, so the not-expired clause is the SOLE reason it survives
  // the sweep -- otherwise the test would pass on the live-timer clause and never exercise the
  // fresh-startTime protection it names (MEDIUM-1).
  Access::registerPending(*t, ID, LOOP, PORT, /*cb=*/{}, /*retryCount=*/1,
                          /*timeout=*/milliseconds(60000),
                          /*startTimeOffset=*/milliseconds(0)); // fresh -> not expired; activeTimerId==0

  REQUIRE(Access::activeTimerIdOf(*t, ID, LOOP, PORT) == 0); // the window under test: no live timer
  Access::callCleanup(*t);

  CHECK(Access::hasPending(*t, ID, LOOP, PORT));        // skipped SOLELY because startTime is fresh
  CHECK(Access::retryCountOf(*t, ID, LOOP, PORT) == 1); // untouched by the sweep
  // ~DnsTransport drains the (callback-less) pending query; no explicit stop() needed (white-box).
}

// =============================================================================================
// KAT 11 (white-box): TC=1 truncation arbitration. When a UDP retransmission is already CLAIMED
// (retryClaimed=true), a concurrently-arriving truncated datagram is DROPPED (retry-wins-first)
// rather than starting a competing TCP fallback -- UDP retry and TCP fallback never both act.
// =============================================================================================
TEST_CASE("dns retry: a truncated response is dropped when a retry is already claimed",
          "[dns][retry][whitebox]")
{
  constexpr std::uint16_t ID = 0x6262;
  constexpr std::uint16_t PORT = 5388;
  constexpr SessionId SID = 1;

  SECTION("retry already claimed -> truncated datagram dropped, no TCP fallback, no burned retry")
  {
    DnsConfig cfg;
    cfg.transportMode = DnsTransportMode::Both; // fallback would otherwise be eligible
    cfg.retryCount = 3;
    auto t = std::make_shared<DnsTransport>(cfg);
    Access::setRunning(*t, true);
    Access::putSession(*t, /*isTcp=*/false, SID, LOOP, PORT); // maps sid -> (server,port)
    Access::registerPending(*t, ID, LOOP, PORT);
    Access::setRetryClaimed(*t, ID, LOOP, PORT, true);

    Access::feedUdp(*t, SID, truncatedResponse(ID));

    // The truncation branch executed (stat bumped before the retryClaimed check) ...
    CHECK(t->getStatistics().truncatedResponses == 1);
    // ... but the retry-wins-first drop fired: query still pending, no fallback, no burned retry.
    CHECK(Access::hasPending(*t, ID, LOOP, PORT));
    CHECK_FALSE(Access::tcpFallbackOf(*t, ID, LOOP, PORT));
    CHECK(Access::retryCountOf(*t, ID, LOOP, PORT) == 0);
  }

  SECTION("no retry claimed -> the same truncated datagram is NOT dropped (non-vacuous)")
  {
    DnsConfig cfg;
    cfg.transportMode = DnsTransportMode::Both;
    cfg.retryCount = 3;
    auto t = std::make_shared<DnsTransport>(cfg);
    Access::setRunning(*t, true);
    Access::installTcpTransport(*t); // sendTcpQuery has a handle to act on
    Access::putSession(*t, /*isTcp=*/false, SID, LOOP, PORT);
    Access::registerPending(*t, ID, LOOP, PORT);
    // retryClaimed defaults to false -> the fallback path is taken.

    Access::feedUdp(*t, SID, truncatedResponse(ID));

    CHECK(t->getStatistics().truncatedResponses == 1);
    // The path did NOT drop: either a fallback was initiated (tcpFallback set) or the query was
    // completed by a fallback-send error. Both differ from the retry-wins-first drop above, which
    // left the query pending with tcpFallback==false.
    bool dropped = Access::hasPending(*t, ID, LOOP, PORT) &&
                   !Access::tcpFallbackOf(*t, ID, LOOP, PORT);
    CHECK_FALSE(dropped);

    t->stop();
  }
}
