# Iora EventBatchProcessor — Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-14 |
| **Status** | IMPLEMENTED |
| **Headers** | `include/iora/network/event_batch_processor.hpp` |
| **Namespace** | `iora::network` |
| **Dependencies** | `<sys/epoll.h>` (Linux `epoll_wait`), `<algorithm>`, `<cerrno>`, `<chrono>`, `<cstdint>`, `<functional>`, `<memory>`, `<mutex>`, `<system_error>`, `<utility>`, `<vector>`. Consumed by `TcpEngine` / `UdpEngine` ([`transport.md`](transport.md)) — each owns one `std::unique_ptr<EventBatchProcessor>`, constructed only when `TransportConfig::batching.enabled`. |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-14 | Initial guide. Documents `EventBatchProcessor`, `BatchProcessingConfig`, `BatchProcessingStats`, the `processBatch` / `processBatchWithSpecialFDs` drain loop, the adaptive-sizing controller, and the three factory presets. Authored against current source during the network-wiki `network_misc` slice. Authoring surfaced two code defects that were fixed inline alongside this guide: (1) `getStats()` now snapshots `stats_` under an internal `statsMutex_`, making it race-free against the I/O thread — the transport engines' public `getStats()` overrides forward here from arbitrary threads; (2) `setFixedBatchSize()` now actually pins the batch bound (`getCurrentBatchSize()` returns `currentBatchSize_` in all modes). This guide documents the fixed behavior. |

---

## 1. Executive Summary

**Problem.** iora's transport engines run one epoll-driven I/O loop per engine. A naïve loop calls `epoll_wait` for a small fixed number of ready descriptors and dispatches them one at a time; under bursty load this pays the `epoll_wait` syscall cost too often and gives the dispatcher no opportunity to amortize per-batch bookkeeping. It also mixes the engine's *control* descriptors (the wakeup `eventfd` and the GC `timerfd`) into the same per-fd dispatch as ordinary session sockets, so every loop body re-tests "is this the eventfd? the timerfd? a session?".

**Solution.** `EventBatchProcessor` is a small, header-only helper that owns a reusable `epoll_event` scratch buffer and drives one **batched drain** per call:

1. It waits once (`epoll_wait`) for up to *N* ready descriptors, where *N* is either a fixed `maxBatchSize` or an **adaptively tuned** current size.
2. It routes each ready descriptor through a caller-supplied **special handler** first (the eventfd / timerfd fast-path), and everything the special handler declines through a **general handler** (session sockets).
3. It records per-batch statistics and, when adaptive sizing is enabled, nudges the batch size up or down based on how full the last batch was and how long it took to process.

**Impact.** The transport engines opt into batching via `TransportConfig::batching.enabled` (**off by default**). When enabled, each engine constructs one processor from the config and calls `processBatchWithSpecialFDs` in its loop, handing it the epoll fd, the eventfd, the timerfd, and three closures (session dispatch, eventfd drain, timerfd/GC). The processor is driven exclusively by its engine's I/O thread; its **only** internal synchronization is a small mutex guarding the statistics struct, so `getStats()` can be polled safely from a monitoring thread (the engines expose exactly that via their public `getStats()` overrides). Everything else — the event buffer, the adaptive current-size — is single-owner-thread state.

---

## 2. System Architecture

### 2.1 Where it sits

```
TransportConfig.batching.enabled == true
        │  (at engine start)
        ▼
TcpEngine / UdpEngine ──owns──► std::unique_ptr<EventBatchProcessor> _batchProcessor
        │
        │  loopBatched()  (the engine I/O thread; the ONLY caller)
        ▼
   _batchProcessor->processBatchWithSpecialFDs(
        _epollFd, _eventFd, _timerFd,
        generalHandler = handleFdEvent(fd, events),   // session/listener sockets
        onEventFd      = drainEvt(); process(),        // queued work wakeups
        onTimerFd      = drainTim(); runGc())          // GC tick
```

When `batching.enabled` is `false` the engine runs its non-batched loop and never constructs a processor. `EventBatchProcessor` is therefore an **optional throughput optimization**, not a required part of the datapath.

### 2.2 Single-owner-thread model (with one synchronized reader)

`EventBatchProcessor` is a **single-owner-thread** object with **one** exception. The contract is that exactly one thread (the owning engine's I/O thread) calls `processBatch*`, `updateConfig`, `setFixedBatchSize`, and `resetStats`. The event buffer (`events_`), the adaptive current-size (`currentBatchSize_`), the last-adjustment timestamp (`lastAdjustment_`), and the config (`config_`) are that thread's private state and carry no lock.

The exception is the **statistics struct** (`stats_`). Because the transport engines expose `getStats()` for off-thread monitoring — `TcpEngine::getStats()` / `UdpEngine::getStats()` forward `_batchProcessor->getStats()` from arbitrary caller threads — `stats_` is written by the I/O thread (in `updateStats` / `adjustBatchSize`) concurrently with those reads. A dedicated `statsMutex_` guards **every** read and write of `stats_` (`updateStats`, the single `adaptiveAdjustments++` site — reached via the shared `adjusted` flag in `adjustBatchSize` — `getStats`, `resetStats`), so **`getStats()` is the one method safe to call from any thread**. Everything else — `resetStats()`, `updateConfig()`, `setFixedBatchSize()`, `getConfig()` — must be called on the owning thread (or while the I/O loop is quiesced): `resetStats()` also writes the unguarded `lastAdjustment_`, and the config mutators write `config_` / `currentBatchSize_` / `events_`. `resetStats()` still takes `statsMutex_` for its `stats_` reset so that reset cannot race a concurrent `getStats()` reader.

### 2.3 Special-fd fast-path

The engine's control descriptors (eventfd wakeup, timerfd GC) must be handled differently from session sockets. Rather than teach the processor about them, `processBatch` takes a **special handler** predicate: for each ready fd it calls `specialHandler(fd, events)` first; a `true` return means "consumed, do not dispatch further". `processBatchWithSpecialFDs` builds that predicate for the common eventfd/timerfd pair so callers pass plain `onEventFd` / `onTimerFd` closures instead.

---

## 3. Component Deep Dive

### 3.1 `BatchProcessingConfig`

| Field | Default | Meaning |
|---|---|---|
| `maxBatchSize` | `64` | Upper bound on descriptors drained per `epoll_wait`; also the size of the reusable event buffer. |
| `maxBatchDelay` | `100 µs` | Requested `epoll_wait` timeout. Rounded **up** to whole milliseconds, floor **1 ms** (`epoll_wait` has ms granularity; the round-up avoids a 0-ms busy-spin). |
| `adaptiveThreshold` | `50 µs` | Per-batch processing-time above which adaptive sizing decreases the batch. |
| `enableAdaptiveSizing` | `true` | Turns the adaptive controller on. When off, the batch size is pinned to `maxBatchSize`. |
| `loadFactor` | `0.75` | Target utilization (`processingTime / maxBatchDelay`); below it the controller may grow the batch, above it it shrinks. |

### 3.2 `BatchProcessingStats`

Plain counters, updated once per non-empty batch: `totalBatches`, `totalEvents`, `maxBatchSize`, `minBatchSize`, `adaptiveAdjustments`, `totalBatchTime`. `getStats()` returns a **copy** with two derived fields filled in on read: `avgBatchTime = totalBatchTime / totalBatches`, and `throughputEventsPerSec = totalEvents / seconds(totalBatchTime)`. Because `totalBatchTime` is measured from **before** `epoll_wait` (it includes the wait), `throughputEventsPerSec` is a conservative wall-clock-inclusive figure, not a pure processing-rate.

### 3.3 Handler types

```cpp
using EventHandler         = std::function<void(int fd, std::uint32_t events)>;
using BatchCompleteHandler = std::function<void(std::size_t batchSize,
                                                std::chrono::microseconds processingTime)>;
```

The **special handler** passed to the template `processBatch` is any callable `bool(int fd, std::uint32_t events)` — returning `true` to claim the fd. `onBatchComplete` is optional and fires once per non-empty batch.

### 3.4 `EventBatchProcessor`

Construction sizes the event buffer to `maxBatchSize` and seeds the adaptive current-size: `maxBatchSize / 2` when adaptive (clamped to at least 1), else `maxBatchSize`.

**`processBatch(epollFd, generalHandler, specialHandler, onBatchComplete = nullptr)`** — one drain:

1. Compute the `epoll_wait` timeout: `max(1, ceil(maxBatchDelay_µs / 1000))` ms.
2. `epoll_wait(epollFd, buffer, currentBatchSize, timeout)`. On `-1` with `errno == EINTR`, return quietly; any other `-1` throws `std::system_error`. On `0` (timeout, no events), return.
3. First pass: for each ready fd, call `specialHandler`; if it returns `true` the fd is consumed, otherwise it is queued into a per-call `normalEvents` vector (bounded by the batch size, reallocated each drain — unlike the reused `events_` scratch buffer, the classify pass is not allocation-free).
4. Second pass: call `generalHandler(fd, events)` for each queued normal event.
5. `updateStats(n, elapsed)`; if adaptive, `adjustBatchSize(n, elapsed)`; then `onBatchComplete(n, elapsed)` if set.

**`processBatchWithSpecialFDs(epollFd, eventFd, timerFd, generalHandler, onEventFd, onTimerFd, onBatchComplete)`** — builds a special handler that maps `eventFd`→`onEventFd`, `timerFd`→`onTimerFd` (each optional), then delegates to `processBatch`.

**`getStats()` / `resetStats()` / `getConfig()` / `updateConfig(config)`** — `updateConfig` replaces the config, resizes the event buffer, and re-seeds the current batch size the same way the constructor does.

**`setFixedBatchSize(size)`** — disables adaptive sizing and pins the current size to `max(1, min(size, maxBatchSize))` (floored to 1 so `setFixedBatchSize(0)`, or any size with `maxBatchSize == 0`, never wedges the drain to a no-op, matching the ctor/`updateConfig` floor). `getCurrentBatchSize()` returns `currentBatchSize_` in all modes, so the pin is honored by `epoll_wait` (its `maxevents` argument). Owner-thread-only. Intended for tests/tuning; the transport engines do not call it.

### 3.5 Adaptive-sizing controller (`adjustBatchSize`)

Runs at most once per **100 ms** (a throttle against thrashing). It computes `utilization = processingTime / maxBatchDelay` and:

- **grows** by ~25 % (min 1, capped at `maxBatchSize`) when the last batch **filled** the current size *and* utilization is below `loadFactor`;
- **shrinks** by ~25 % (min 1, floor 1) when processing time exceeds `adaptiveThreshold` *or* utilization exceeds `loadFactor`.

Each adjustment increments `adaptiveAdjustments`. Note that because the measured time includes the `epoll_wait` wait, a lightly loaded processor sees high utilization and tends to shrink toward the floor — which is the intended low-latency behavior.

### 3.6 Factory presets

| Helper | `maxBatchSize` | `maxBatchDelay` | `adaptiveThreshold` | `loadFactor` | Intent |
|---|---|---|---|---|---|
| `createOptimizedProcessor(expectedLoad = 32)` | `max(8, expectedLoad*2)` | `50 µs` | `25 µs` | `0.7` | Balanced low-latency default. |
| `createHighThroughputProcessor()` | `128` | `200 µs` | `150 µs` | `0.8` | Favor batching / utilization. |
| `createLowLatencyProcessor()` | `16` | `10 µs` | `5 µs` | `0.5` | Favor latency over utilization. |

All three enable adaptive sizing and return a `std::unique_ptr<EventBatchProcessor>`.

---

## 4. Usage Guide

### 4.1 Engine integration (the real consumer)

The transport engines wire the processor automatically when batching is enabled:

```cpp
// TransportConfig
cfg.batching.enabled            = true;   // off by default
cfg.batching.maxBatchSize       = 64;
cfg.batching.maxBatchDelay      = std::chrono::microseconds(100);
cfg.batching.enableAdaptiveSizing = true;
// ... engine constructs one EventBatchProcessor from cfg.batching and
//     calls processBatchWithSpecialFDs in its I/O loop.
```

No application code touches the processor directly — it is an engine-internal optimization selected by config.

### 4.2 Standalone use

```cpp
#include <iora/network/event_batch_processor.hpp>

// epollFd / eventFd / timerFd come from your own epoll setup;
// `running` is your loop's shutdown flag.
iora::network::BatchProcessingConfig cfg;
cfg.maxBatchSize = 32;
cfg.maxBatchDelay = std::chrono::milliseconds(10);
cfg.enableAdaptiveSizing = false;
iora::network::EventBatchProcessor processor(cfg);

auto onSession = [](int fd, std::uint32_t events) { /* handle session fd */ };
auto onEventFd = [] { /* drain wakeup */ };
auto onTimerFd = [] { /* run periodic work */ };

// Drive from ONE thread (the epoll owner):
while (running) {
  try {
    processor.processBatchWithSpecialFDs(epollFd, eventFd, timerFd,
                                         onSession, onEventFd, onTimerFd);
  } catch (const std::system_error&) {
    // epoll_wait EINTR is swallowed inside processBatch; any other errno
    // surfaces here — log/continue as the engine loop does.
    continue;
  }
}
```

### 4.3 Gotchas & anti-patterns

- **One driver thread only, except `getStats()`.** Never call `processBatch*`, `updateConfig`, `setFixedBatchSize`, or `resetStats` from anything but the owning thread. `getStats()` is the one method safe to poll from a monitoring thread while the owner runs (it snapshots `stats_` under `statsMutex_`, §7).
- **`generalHandler` / `specialHandler` run inline** on the driver thread — keep them non-blocking, exactly like an epoll dispatch body.
- **`epoll_wait` errors throw.** Only `EINTR` is swallowed; wrap the call as the engine does (catch `std::system_error`, continue).
- **`maxBatchDelay` sub-millisecond values round up to 1 ms** — you cannot get a sub-ms batch window from `epoll_wait`.

---

## 5. Call Flow / Sequence Reference

### 5.1 One `processBatchWithSpecialFDs` iteration

1. Driver thread calls the method with the epoll fd, control fds, and closures.
2. A special-handler lambda is built for `eventFd`/`timerFd`; `processBatch` runs.
3. `epoll_wait` blocks up to the rounded timeout, returns `n` ready descriptors (or `0`/`EINTR`).
4. First pass classifies each fd: control fds fire `onEventFd`/`onTimerFd` and are consumed; the rest are queued.
5. Second pass dispatches queued session fds through `generalHandler`.
6. Stats update; adaptive controller may resize; `onBatchComplete` fires.
7. Control returns to the engine loop, which loops again.

---

## 6. Configuration Reference

`BatchProcessingConfig` fields and defaults are in §3.1. The transport engines map their own `TransportConfig::batching` sub-struct (`BatchConfig`) onto it:

| `TransportConfig::batching` field | Default | Maps to |
|---|---|---|
| `enabled` | `false` | Whether the engine constructs a processor at all. |
| `maxBatchSize` | `64` | `BatchProcessingConfig::maxBatchSize` |
| `maxBatchDelay` | `100 µs` | `BatchProcessingConfig::maxBatchDelay` |
| `adaptiveThreshold` | `50 µs` | `BatchProcessingConfig::adaptiveThreshold` |
| `enableAdaptiveSizing` | `true` | `BatchProcessingConfig::enableAdaptiveSizing` |
| `loadFactor` | `0.75` | `BatchProcessingConfig::loadFactor` |

`updateConfig()` re-applies all fields at runtime and re-sizes the event buffer; the three factory presets in §3.6 are convenience constructors of the same config.

---

## 7. Thread Safety Model

`EventBatchProcessor` is a **single-owner-thread** object with one synchronized reader. It holds exactly one lock, `statsMutex_`, which guards the statistics struct so the object can be polled for stats off-thread.

| State | Access |
|---|---|
| `stats_` (counters) | Written by the owner thread (`updateStats` / `adjustBatchSize`) and read by `getStats()` from any thread — **every** access under `statsMutex_`. |
| `events_` (epoll scratch buffer), `currentBatchSize_`, `lastAdjustment_`, `config_` | Owner-thread-only; no lock. |

- **`getStats()` is safe to call from any thread.** It copies `stats_` under `statsMutex_`, then computes the derived fields (`avgBatchTime`, `throughputEventsPerSec`) on the local copy outside the lock. The transport engines' public `getStats()` overrides forward here from arbitrary monitoring threads — that off-thread read is the reason the lock exists.
- **All mutating methods** (`processBatch*`, `updateConfig`, `setFixedBatchSize`, `resetStats`) must run on the one owner thread. `resetStats()` also writes the unguarded `lastAdjustment_`, so it is owner-thread-only despite locking `statsMutex_` for its `stats_` reset (that lock only protects the reset against a concurrent `getStats()` reader). `getConfig()` reads owner-thread-only `config_`; the engines never call it cross-thread.
- **`statsMutex_` is a strict leaf:** it is never held across `epoll_wait`, across a handler callback (`generalHandler` / `specialHandler` / `onBatchComplete`), or nested with any other lock — the engine `getStats()` overrides hold no engine mutex across the forwarded call, so no lock-order inversion is possible.
- The handlers are invoked **inline on the owner thread**; any cross-thread state they touch is their own responsibility.

The transport engines satisfy this contract: they drive `processBatch*` solely from their I/O thread and forward `getStats()` from monitoring threads — exactly the two access modes the lock supports.

---

## 8. API Reference

```cpp
// iora::network — event_batch_processor.hpp

struct BatchProcessingConfig {
  std::size_t maxBatchSize{64};
  std::chrono::microseconds maxBatchDelay{100};
  std::chrono::microseconds adaptiveThreshold{50};
  bool enableAdaptiveSizing{true};
  double loadFactor{0.75};
};

struct BatchProcessingStats {
  std::uint64_t totalBatches{0};
  std::uint64_t totalEvents{0};
  std::uint64_t maxBatchSize{0};
  std::uint64_t minBatchSize{0};
  std::uint64_t adaptiveAdjustments{0};
  std::chrono::microseconds totalBatchTime{0};
  std::chrono::microseconds avgBatchTime{0};       // derived on getStats()
  double throughputEventsPerSec{0.0};              // derived on getStats()
};

using EventHandler         = std::function<void(int fd, std::uint32_t events)>;
using BatchCompleteHandler = std::function<void(std::size_t batchSize,
                                                std::chrono::microseconds processingTime)>;

class EventBatchProcessor {
public:
  explicit EventBatchProcessor(const BatchProcessingConfig& config = {});

  template <typename SpecialEventHandler>
  void processBatch(int epollFd, const EventHandler& generalHandler,
                    const SpecialEventHandler& specialHandler,   // bool(int fd, std::uint32_t)
                    const BatchCompleteHandler& onBatchComplete = nullptr);

  void processBatchWithSpecialFDs(int epollFd, int eventFd, int timerFd,
                                  const EventHandler& generalHandler,
                                  const std::function<void()>& onEventFd = nullptr,
                                  const std::function<void()>& onTimerFd = nullptr,
                                  const BatchCompleteHandler& onBatchComplete = nullptr);

  BatchProcessingStats getStats() const;
  void resetStats();
  void updateConfig(const BatchProcessingConfig& config);
  BatchProcessingConfig getConfig() const;
  void setFixedBatchSize(std::size_t size);        // disables adaptive; pins the batch bound (owner-thread-only)
};

std::unique_ptr<EventBatchProcessor> createOptimizedProcessor(std::size_t expectedLoad = 32);
std::unique_ptr<EventBatchProcessor> createHighThroughputProcessor();
std::unique_ptr<EventBatchProcessor> createLowLatencyProcessor();
```

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Reusable `epoll_event` buffer sized to `maxBatchSize` | Avoids a per-batch allocation; the buffer is filled by `epoll_wait` and consumed in place. |
| Special-handler predicate instead of hard-coded control fds | Keeps the processor decoupled from the engine's eventfd/timerfd identities; `processBatchWithSpecialFDs` provides the common convenience. |
| Two-pass dispatch (classify, then run general handlers) | Lets control descriptors be serviced first and separates the concerns cleanly; the intermediate `normalEvents` vector is small (≤ batch size). |
| `EINTR` swallowed, other errors thrown | A signal-interrupted `epoll_wait` is normal and retried by the loop; a real error is surfaced to the engine, which logs and continues. |
| One lock (`statsMutex_`) guarding only `stats_` | The object is single-owner-thread except for `getStats()`, which the engines poll from monitoring threads. A leaf mutex over the stats snapshot is the minimum needed; the hot dispatch path (buffer, adaptive size) stays lock-free. |
| `maxevents` clamped to `events_.size()` (skip drain if empty) | A degenerate `maxBatchSize == 0` sizes the buffer to 0 while the current-size floor is 1; passing an unclamped `maxevents` would overrun the buffer. The clamp makes it a safe no-op. |
| Adaptive sizing throttled to 100 ms | Prevents the controller from oscillating on every batch. |

---

## 10. Known Limitations

- **Only `getStats()` is cross-thread-safe.** The rest of the object (including `resetStats()` and the config mutators) is owner-thread-only (§7). `getStats()`'s derived `throughputEventsPerSec` is wall-clock-inclusive (it counts `epoll_wait` wait time), so it under-reports the pure processing rate.
- **A `maxBatchSize == 0` config drains nothing.** The buffer is empty, so `processBatch` clamps `maxevents` to 0 and returns immediately — a safe no-op, not an error. A meaningful config needs `maxBatchSize >= 1`.
- **Millisecond timeout granularity.** `maxBatchDelay` below 1 ms rounds up to 1 ms — the smallest `epoll_wait` window.
- **Batching is off by default** in the transport (`TransportConfig::batching.enabled == false`); the processor is an opt-in optimization, not part of the default datapath.
