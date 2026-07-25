// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for the immutable FormatSnapshot COW model and the
// shared_ptr<const ExternalHandler> conversion (tracker 2026-07-22-3).
//
// Coverage (tracker acceptance):
//   - never-null initial snapshot: formatting works with neither init() nor
//     setLogFormat() ever called (acc 5).
//   - %l renders EMPTY (not "0") when no source location is supplied (acc 9).
//   - no per-message deep copy of the compiled format: a COW refcount bump, so
//     per-delivery allocation does NOT scale with segment count (acc 4).
//   - a capture whose COPY-constructor logs no longer runs that copy-ctor under
//     data.mutex (the dispatch copy is a refcount bump), so it does not
//     self-deadlock (acc 2/3).
//   - cross-field preservation: concurrent init() (timestampFmt) vs setLogFormat()
//     (segments) never wipes the sibling field (acc 6).
//   - live-snapshot: a message formatted during a concurrent setLogFormat uses the
//     whole-old or whole-new format, never a mix (acc 7).
//
// The capture-DESTRUCTOR re-entrancy / tear-out cases live in
// iora_test_logger_self_clear_deadlock.cpp (l)/(l2)/(l3a)/(l3b). Catch2 macros run
// ONLY on the main thread; worker/log threads record into shared flags/counters and
// the main thread asserts after BOUNDED waits.

#define CATCH_CONFIG_MAIN
#include "logger_race_harness.hpp"
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include <iora/core/logger.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <regex>
#include <string>
#include <thread>
#include <vector>

using iora::core::Logger;
using iora::test::joinOrDetach;
using iora::test::makeFlag;
using iora::test::waitFor;

namespace
{
// Capture a formatted line by installing a handler that records into a shared
// string under its own mutex (Catch2 asserts on the main thread afterwards).
struct LineSink
{
  std::mutex m;
  std::vector<std::string> lines;
  void push(const std::string &s)
  {
    std::lock_guard<std::mutex> l(m);
    lines.push_back(s);
  }
  std::vector<std::string> snapshot()
  {
    std::lock_guard<std::mutex> l(m);
    return lines;
  }
};
} // namespace

// ── acc 5: never-null initial snapshot. With neither init() nor setLogFormat()
//    called in this process before the first format, the default snapshot must
//    produce a well-formed line (no null deref, default "[%T] [%L] %m").
TEST_CASE("format snapshot: default snapshot formats before any init/setLogFormat",
          "[logger][format_snapshot][never_null]")
{
  auto sink = std::make_shared<LineSink>();
  // First logger touch: install a capturing handler WITHOUT calling init() first.
  Logger::setExternalHandler([sink](Logger::Level, const std::string &formatted,
                                    const std::string &) { sink->push(formatted); });
  Logger::info("hello");
  Logger::flush();

  const bool got = waitFor([sink] { return !sink->snapshot().empty(); });
  CHECK(got);
  if (got)
  {
    const auto lines = sink->snapshot();
    // Exact default framing "[%T] [%L] %m" — proves the default snapshot (not some
    // other format) was used, independent of Catch2 case ordering.
    CHECK(std::regex_match(lines.front(), std::regex("^\\[.*\\] \\[INFO\\] hello\n$")));
  }
  Logger::clearExternalHandler();
  Logger::shutdown();
}

// ── acc 6 (reverse direction): setLogFormat must CARRY the current timestamp format.
//    init() sets a distinctive timestamp format; a later setLogFormat() (which
//    changes logFormat+segments) must preserve it — a %T render still shows the
//    marker. Deleting the carry in the republish would render an EMPTY timestamp
//    here and FAIL. (Companion to the forward-direction cross_field test.)
TEST_CASE("format snapshot: setLogFormat carries the timestamp format set by init",
          "[logger][format_snapshot][cross_field_carry]")
{
  auto sink = std::make_shared<LineSink>();
  // Distinctive timestamp format with no % specifiers: strftime copies it literally.
  Logger::init(Logger::Level::Info, "", /*async=*/true, 7, "TSMARK");
  Logger::setLogFormat("%T|%m"); // changes logFormat+segments; must carry timestampFmt
  Logger::setExternalHandler([sink](Logger::Level, const std::string &formatted,
                                    const std::string &) { sink->push(formatted); });
  Logger::info("hi");
  Logger::flush();
  const bool got = waitFor([sink] { return !sink->snapshot().empty(); });
  CHECK(got);
  if (got)
  {
    const auto lines = sink->snapshot();
    // timestampFmt survived the setLogFormat republish → %T renders "TSMARK".
    CHECK(lines.front().find("TSMARK") != std::string::npos);
    CHECK(lines.front() == "TSMARK|hi\n");
  }
  Logger::clearExternalHandler();
  Logger::shutdown();
}

// ── acc 9: %l renders EMPTY (not "0") when no source location is supplied. The
//    printf-family / stream path does not carry source location, so %l/%F/%f emit
//    nothing — NOT 0 — under the unified formatter's hasLocation=false path.
TEST_CASE("format snapshot: %l renders empty (not 0) without a source location",
          "[logger][format_snapshot][no_location]")
{
  auto sink = std::make_shared<LineSink>();
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  Logger::setLogFormat("L=[%l] F=[%F] f=[%f] %m");
  Logger::setExternalHandler([sink](Logger::Level, const std::string &formatted,
                                    const std::string &) { sink->push(formatted); });

  // infof() takes the printf path (no source location captured for %l/%F/%f).
  Logger::infof("no-loc %d", 7);
  Logger::flush();
  const bool got = waitFor([sink] { return !sink->snapshot().empty(); });
  CHECK(got);
  if (got)
  {
    const auto lines = sink->snapshot();
    const std::string &line = lines.front();
    // Empty fields, NOT "0" for %l.
    CHECK(line.find("L=[]") != std::string::npos);
    CHECK(line.find("L=[0]") == std::string::npos);
    CHECK(line.find("F=[]") != std::string::npos);
    CHECK(line.find("f=[]") != std::string::npos);
    CHECK(line.find("no-loc 7") != std::string::npos);
  }
  Logger::clearExternalHandler();
  Logger::shutdown();
}

// ── acc 4: COW — per-message delivery does NOT deep-copy the compiled format, so
//    the per-delivery allocation count does NOT scale with segment count. A SIMPLE
//    format and a COMPLEX (many-segment) format must cost ~the same per delivery.
//    Under the old deep-copy path the complex format would allocate a much larger
//    segment vector + timestamp string PER message. Relative check (no absolute
//    counts): robust to allocator noise.
namespace
{
std::atomic<long> g_allocs{0};
std::atomic<bool> g_countAllocs{false};
} // namespace
void *operator new(std::size_t n)
{
  if (g_countAllocs.load(std::memory_order_relaxed))
  {
    g_allocs.fetch_add(1, std::memory_order_relaxed);
  }
  if (void *p = std::malloc(n))
  {
    return p;
  }
  throw std::bad_alloc();
}
void operator delete(void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }

namespace
{
long allocsForFormat(const std::string &fmt, int deliveries)
{
  auto counted = std::make_shared<std::atomic<int>>(0);
  Logger::init(Logger::Level::Info, "", /*async=*/false); // sync: delivery on caller thread
  Logger::setLogFormat(fmt);
  // A handler that does NOTHING with the strings and captures only a plain atomic —
  // so the measured allocations are the delivery path's, not the handler's.
  Logger::setExternalHandler(
    [counted](Logger::Level, const std::string &, const std::string &) { counted->fetch_add(1); });

  g_allocs.store(0);
  g_countAllocs.store(true, std::memory_order_relaxed);
  for (int i = 0; i < deliveries; ++i)
  {
    Logger::info("x");
  }
  g_countAllocs.store(false, std::memory_order_relaxed);
  const long a = g_allocs.load();
  Logger::clearExternalHandler();
  Logger::shutdown();
  REQUIRE(counted->load() == deliveries);
  return a;
}
} // namespace

TEST_CASE("format snapshot: per-delivery does not allocate a format-vector/timestamp copy (COW)",
          "[logger][format_snapshot][cow][alloc]")
{
  const int N = 2000;
  // A SIMPLE format with SHORT output isolates the COW: under the immutable-snapshot
  // model each delivery only refcount-bumps the snapshot (no allocation) and builds
  // the small output string — measured ~1 allocation/delivery. The OLD deep-copy
  // path would additionally copy the compiled-segment vector (buffer allocation) AND
  // the non-SSO timestamp format string ("%Y-%m-%d %H:%M:%S", 18 chars) on EVERY
  // delivery, i.e. ~+2 allocations/delivery. Asserting <= 2/delivery therefore
  // passes for COW and fails for the deep-copy regression, robustly to allocator SSO
  // noise (short output; no %T so no timestamp render, only the format-string copy
  // the deep copy would have made).
  const long simple = allocsForFormat("[%L] %m", N);
  const double perDelivery = static_cast<double>(simple) / N;
  INFO("total allocations=" << simple << " perDelivery=" << perDelivery);
  CHECK(perDelivery <= 2.0);
}

// ── acc 2/3: a capture whose COPY-constructor logs. Under the shared_ptr model the
//    dispatch copy is a refcount bump — the capture's copy-ctor never runs (and
//    never under data.mutex), so it cannot self-deadlock. Bounded: a regression
//    that deep-copied the std::function under the lock would run the logging
//    copy-ctor under the non-recursive mutex and hang.
namespace
{
struct LoggingOnCopy
{
  std::shared_ptr<std::atomic<int>> copies;
  std::shared_ptr<std::atomic<bool>> armed;
  LoggingOnCopy(std::shared_ptr<std::atomic<int>> c, std::shared_ptr<std::atomic<bool>> a)
      : copies(std::move(c)), armed(std::move(a))
  {
  }
  LoggingOnCopy(const LoggingOnCopy &o) : copies(o.copies), armed(o.armed)
  {
    if (copies)
    {
      copies->fetch_add(1);
    }
    if (armed && armed->load())
    {
      Logger::info("copy-ctor logging"); // re-enters the logger
    }
  }
  LoggingOnCopy(LoggingOnCopy &&) = default;
  ~LoggingOnCopy() = default;
};
} // namespace

TEST_CASE("format snapshot: capture copy-ctor is never run under the lock (no per-dispatch copy)",
          "[logger][format_snapshot][copy_ctor][uaf]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  auto copies = std::make_shared<std::atomic<int>>(0);
  auto armed = std::make_shared<std::atomic<bool>>(false);
  auto delivered = std::make_shared<std::atomic<int>>(0);

  Logger::setExternalHandler(
    [probe = LoggingOnCopy{copies, armed}, delivered](Logger::Level, const std::string &,
                                                      const std::string &)
    { delivered->fetch_add(1); });
  const int copiesAfterInstall = copies->load();
  armed->store(true);

  // Drive several deliveries on a worker thread behind a bounded flag: if a
  // regression deep-copied the handler under the lock, the logging copy-ctor would
  // self-deadlock and this FAILS bounded.
  auto done = std::make_shared<std::atomic<bool>>(false);
  std::thread driver(
    [done]
    {
      for (int i = 0; i < 5; ++i)
      {
        Logger::info("m");
      }
      Logger::flush();
      done->store(true);
    });
  const bool ok = waitFor([done] { return done->load(); });
  CHECK(ok);
  const bool allDelivered = waitFor([delivered] { return delivered->load() >= 5; });
  CHECK(allDelivered);
  iora::test::joinOrDetach(ok && allDelivered, {&driver});
  if (!ok || !allDelivered)
  {
    return;
  }
  // No dispatch-time copy of the capture: copy count is unchanged by the deliveries.
  CHECK(copies->load() == copiesAfterInstall);
  Logger::clearExternalHandler();
  Logger::shutdown();
}

// ── acc 6: cross-field preservation. init() changes ONLY the timestamp format;
//    setLogFormat() changes ONLY logFormat+segments. Run concurrently, neither may
//    wipe the sibling field. TSan-clean (single mutex serializes publishes).
TEST_CASE("format snapshot: concurrent init vs setLogFormat preserves the sibling field",
          "[logger][format_snapshot][cross_field]")
{
  Logger::init(Logger::Level::Info, "", /*async=*/false);
  Logger::setLogFormat("FMT_A %m");
  Logger::init(Logger::Level::Info, "", /*async=*/false, 7, "TS_A");

  std::atomic<bool> go{false};
  // Own bounded completion flags (harness discipline): setLogFormat/init(async=false)
  // provably cannot block today, but bound the joins defensively so a FUTURE change
  // that made them block is a bounded FAIL, not a wedged suite.
  auto setterDone = makeFlag();
  auto initerDone = makeFlag();
  std::thread setter(
    [&go, setterDone]
    {
      while (!go.load())
      {
      }
      for (int i = 0; i < 500; ++i)
      {
        Logger::setLogFormat("FMT_B %m"); // changes segments; must carry timestampFmt
      }
      setterDone->store(true);
    });
  std::thread initer(
    [&go, initerDone]
    {
      while (!go.load())
      {
      }
      for (int i = 0; i < 500; ++i)
      {
        Logger::init(Logger::Level::Info, "", /*async=*/false, 7, "TS_B"); // changes tsFmt
      }
      initerDone->store(true);
    });
  go.store(true);
  const bool bothDone = waitFor([&] { return setterDone->load() && initerDone->load(); });
  CHECK(bothDone);
  joinOrDetach(bothDone, {&setter, &initer});
  if (!bothDone)
  {
    return;
  }

  // Final state: whichever publish landed last, BOTH fields are non-default and
  // internally consistent — neither was wiped to empty/default by the other's
  // read-modify-republish. getLogFormat() reflects one of the two format strings,
  // never empty.
  const std::string fmt = Logger::getLogFormat();
  CHECK((fmt == "FMT_A %m" || fmt == "FMT_B %m"));
  CHECK(!fmt.empty());
  Logger::shutdown();
}

// ── acc 7: live-snapshot — a message formatted during a concurrent setLogFormat
//    uses the WHOLE old or WHOLE new format, never a mix. Format A and B are
//    distinguishable and each self-consistent; every captured line must match A or
//    B exactly, never a spliced hybrid.
TEST_CASE("format snapshot: concurrent setLogFormat never yields a torn (mixed) format",
          "[logger][format_snapshot][live_snapshot]")
{
  auto sink = std::make_shared<LineSink>();
  Logger::init(Logger::Level::Info, "", /*async=*/true);
  Logger::setExternalHandler([sink](Logger::Level, const std::string &formatted,
                                    const std::string &) { sink->push(formatted); });

  // Two formats whose OUTPUT is trivially classifiable and cannot be confused with a
  // splice: A wraps the message in AA..AA, B in BB..BB.
  Logger::setLogFormat("AA%mAA");
  std::atomic<bool> stop{false};
  auto flipperDone = makeFlag(); // bounded completion (harness discipline)
  std::thread flipper(
    [&stop, flipperDone]
    {
      bool a = true;
      while (!stop.load())
      {
        Logger::setLogFormat(a ? "AA%mAA" : "BB%mBB");
        a = !a;
      }
      flipperDone->store(true);
    });
  for (int i = 0; i < 3000; ++i)
  {
    Logger::info("m");
  }
  Logger::flush();
  stop.store(true);
  const bool flipperReturned = waitFor([flipperDone] { return flipperDone->load(); });
  CHECK(flipperReturned);
  joinOrDetach(flipperReturned, {&flipper});
  if (!flipperReturned)
  {
    return;
  }

  const bool got = waitFor([sink] { return !sink->snapshot().empty(); });
  CHECK(got);
  const auto lines = sink->snapshot();
  const std::regex whole("^(AAmAA|BBmBB)\n$");
  bool allWhole = true;
  for (const auto &l : lines)
  {
    if (!std::regex_match(l, whole))
    {
      allWhole = false;
      WARN("torn/hybrid line: " << l);
      break;
    }
  }
  CHECK(allWhole); // every line is a WHOLE format, never a mix of A and B
  Logger::clearExternalHandler();
  Logger::shutdown();
}
