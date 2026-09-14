# Iora Network Resiliency: Circuit Breaking & Connection Health — Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-14 |
| **Status** | IMPLEMENTED |
| **Headers** | `include/iora/network/circuit_breaker.hpp`, `include/iora/network/connection_health.hpp` |
| **Namespace** | `iora::network` |
| **Dependencies** | `<atomic>`, `<chrono>`, `<cstdint>`, `<functional>`, `<memory>`, `<mutex>`, `<string>`, `<unordered_map>`, `<utility>`, `<vector>` (circuit breaker); `network/transport_types.hpp` (for `SessionId`), `<algorithm>`, `<atomic>`, `<chrono>`, `<cstddef>`, `<cstdint>`, `<memory>`, `<mutex>`, `<unordered_map>`, `<utility>`, `<vector>` (connection health) |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-14 | Initial guide. Documents `CircuitBreaker`/`CircuitBreakerManager` and `ConnectionHealth`/`HealthMonitor` as standalone, application-composable primitives. Records that the transport layer does not auto-wire either primitive (the dead auto-wire members and the no-op `autoHealthMonitoring` flag were removed in iora `7f38bcb`). |

---

## 1. Executive Summary

### Problem

A service that calls a flaky downstream — an HTTP backend, a SIP registrar, a database — needs two distinct resilience behaviors, and hand-rolling either one per call site is where the bugs live:

- **Fail fast when a dependency is down.** Without a circuit breaker, every request to a dead backend pays the full connect/timeout cost, threads pile up waiting, and the failure cascades back into the caller. The correct behavior — stop calling for a cooldown, then probe before resuming — is a small state machine that is easy to get subtly wrong (when exactly to re-probe, how many successes close it, when a probe failure reopens it).
- **Track per-connection health as a rolling signal.** A long-lived connection degrades before it dies: intermittent failures, silence past a heartbeat interval. Code that reacts only to a hard close reacts too late.

### Solution

This component provides two **independent** primitives (they share no code and no keys) plus a registry for each:

- **`CircuitBreaker`** — a lock-free Closed → Open → HalfOpen state machine driven by `allowRequest()` / `recordSuccess()` / `recordFailure()`. Trips open on an absolute failure count or a failure *rate*, waits a configurable timeout, then admits probes.
- **`CircuitBreakerManager`** — a mutex-guarded `std::string`-name → breaker registry, so one process can protect many named dependencies independently.
- **`ConnectionHealth`** — a lock-free per-connection tracker that folds success/failure/activity into a five-level `ConnectionState` (Healthy → Warning → Degraded → Critical → Unhealthy), plus heartbeat-due and timeout predicates.
- **`HealthMonitor`** — a mutex-guarded `SessionId` → health registry with aggregate `OverallStats`.

### Technical Impact

- **O(1)** hot path for both primitives: a `CircuitBreaker` request decision and a `ConnectionHealth` record are a handful of relaxed atomic operations, no lock.
- **Registry lookups** (`CircuitBreakerManager`, `HealthMonitor`) are one `std::unordered_map` probe under a short-held mutex; the returned/owned primitive is then operated lock-free.
- **Minimal transport coupling:** `circuit_breaker.hpp` includes no transport headers and is usable in any C++17 code. In the health family, only `HealthMonitor`'s registry key is the transport `SessionId`; `ConnectionHealth` itself carries no transport type.

---

## 2. System Architecture

### Component Relationships

The two families are deliberately **separate** — there is no aggregate "resilience manager", and neither primitive references the other.

```
iora::network
│
├── Circuit-breaking family  (circuit_breaker.hpp — generic, no transport dependency)
│   ├── CircuitBreakerConfig        value struct (thresholds, timeout, rate)
│   ├── CircuitBreakerState         enum { Closed, Open, HalfOpen }
│   ├── CircuitBreaker              lock-free state machine (5 atomics + plain config)
│   │       allowRequest / recordSuccess / recordFailure / getState / getStats / reset
│   └── CircuitBreakerManager       mutex + unordered_map<std::string, unique_ptr<CircuitBreaker>>
│           owns the breakers (created via BreakerFactory; never erased)
│
└── Connection-health family  (connection_health.hpp — registry keyed by transport SessionId)
    ├── HealthConfig                value struct (heartbeat/timeout/failure thresholds)
    ├── ConnectionState             enum { Healthy, Warning, Degraded, Critical, Unhealthy }
    ├── ConnectionHealth            lock-free per-connection tracker (5 atomics + plain config)
    │       recordActivity / recordFailure / recordSuccess / isHealthy / needsHeartbeat
    │       isTimedOut / getState / getStats
    └── HealthMonitor               mutex + unordered_map<SessionId, unique_ptr<ConnectionHealth>>
            owns per-session trackers; aggregates OverallStats
```

**Layering (why they are not one class).** `CircuitBreaker` is a *generic* fault-tolerance primitive: it knows nothing about connections, sessions, or the transport, and `CircuitBreakerManager`'s registry is keyed by an arbitrary `std::string` service name. `ConnectionHealth` is likewise self-contained — it holds no `SessionId`; it is *transport-adjacent* only because its registry, `HealthMonitor`, is keyed by `iora::network::SessionId` (from `transport_types.hpp`). They live at different layers, address different questions ("should I call this dependency?" vs. "is this specific connection degrading?"), and are paired in one guide only because the README groups them and each is thin — not because they collaborate.

**Ownership.** Both managers own their child primitives through `std::unique_ptr` inside an `unordered_map`. `CircuitBreakerManager` has **no removal API** — a breaker, once created, lives for the manager's lifetime, which is what makes the reference returned by `getBreaker()` safe to hold and use lock-free. `HealthMonitor` *does* support `removeConnection()`, so a raw `ConnectionHealth*` must never outlive the monitor lock that produced it (the monitor never hands one out; it calls through internally).

### Data Flow: guarding a downstream call

```mermaid
sequenceDiagram
    participant App as Caller
    participant CB as CircuitBreaker
    participant Dep as Downstream

    App->>CB: allowRequest()
    alt state == Open and timeout not elapsed
        CB-->>App: false (fail fast)
        Note over App: skip the call entirely
    else Closed, or Open->HalfOpen probe, or HalfOpen
        CB-->>App: true
        App->>Dep: perform request
        alt success
            Dep-->>App: ok
            App->>CB: recordSuccess()
            Note over CB: HalfOpen + enough successes -> Closed
        else failure/exception
            Dep-->>App: error
            App->>CB: recordFailure()
            Note over CB: Closed + threshold/rate exceeded -> Open;<br/>HalfOpen failure -> Open
        end
    end
```

### Threading Model

| Thread | Responsibility |
|---|---|
| Any caller thread | Drives a `CircuitBreaker` / `ConnectionHealth` directly via its record/query methods (lock-free). |
| Any caller thread | Drives a `CircuitBreakerManager` / `HealthMonitor`; registry structure is protected by the manager's mutex, the per-child primitive by its own atomics. |
| (none) | There is **no background thread.** Neither primitive owns a timer or worker. Cooldown expiry, heartbeat-due, and timeout are computed lazily from `steady_clock::now()` at query time. The application must poll (e.g. call `needsHeartbeat()` / `getUnhealthyConnections()` on its own cadence). |

---

## 3. Component Deep Dive

### 3.1 CircuitBreaker

A lock-free state machine over five atomics (`_state`, `_failureCount`, `_successCount`, `_lastFailureTime`, `_requestCount`) plus a plain `_config`.

**States.** `CircuitBreakerState::Closed` (normal — requests flow), `Open` (failing fast — requests rejected until the cooldown elapses), `HalfOpen` (probing — requests are admitted to test recovery; see the caveat below).

**`allowRequest()`** returns whether the caller should proceed:

```cpp
switch (_state.load(std::memory_order_relaxed))
{
case CircuitBreakerState::Closed:
  return true;
case CircuitBreakerState::Open:
{
  auto lastFailure = _lastFailureTime.load(std::memory_order_relaxed);
  if (now - lastFailure >= _config.timeout)
  {
    auto expected = CircuitBreakerState::Open;
    if (_state.compare_exchange_strong(expected, CircuitBreakerState::HalfOpen,
                                       std::memory_order_relaxed))
    {
      _successCount.store(0, std::memory_order_relaxed);
    }
    return true;
  }
  return false;
}
case CircuitBreakerState::HalfOpen:
  return true;   // admit request
default:
  return false;
}
```

The Open → HalfOpen transition uses a `compare_exchange_strong`, so exactly one thread wins the transition and resets `_successCount`; both the winner and any racing thread return `true`.

**HalfOpen admits *every* request — there is no probe cap.** Once the breaker is HalfOpen, `allowRequest()` returns `true` for every caller until either a success run reaches `successThreshold` (closing it) or a single failure reopens it. It does **not** admit only one probe or throttle concurrency, so under load a HalfOpen breaker forwards the full request volume to a possibly-still-sick backend. This is a deliberate simplification, not a bug, but callers must not rely on HalfOpen for thundering-herd protection (see §4 and §10).

**`recordFailure()`** stamps `_lastFailureTime = now`, increments `_failureCount` and `_requestCount`. If the current state is `HalfOpen`, it drops straight back to `Open`. If `Closed`, it consults `shouldOpenCircuit()`.

**`recordSuccess()`** increments `_requestCount`. In `HalfOpen`, once `_successCount` reaches `config.successThreshold` it closes the circuit and zeroes the failure/success counters. In `Closed`, a success zeroes `_failureCount` (so isolated failures don't accumulate forever).

**`shouldOpenCircuit(failures)`** trips open when **either** an absolute count **or** a rate is exceeded:

```cpp
if (failures >= _config.failureThreshold) { return true; }
auto requests = _requestCount.load(std::memory_order_relaxed);
if (static_cast<int>(requests) >= _config.minimumRequests)
{
  double failureRate = static_cast<double>(failures) / requests;
  return failureRate >= _config.failureRateThreshold;
}
return false;
```

Note the time-base mismatch between the two operands: `failures` is `_failureCount`, which a single `Closed` success zeroes (see `recordSuccess()`), so it is effectively the *current consecutive*-failure streak; `_requestCount` is a **lifetime** counter cleared only by `reset()`. The rate rule therefore only becomes meaningful during an uninterrupted failure streak — at which point the absolute `failureThreshold` usually trips first. In practice `failureThreshold` is the dominant trigger and `failureRateThreshold`/`minimumRequests` rarely fire on their own; tune with that in mind (see §10).

**Copy/move.** Not explicitly declared. Because the members are `std::atomic`, the class is neither copyable nor movable (atomics delete both) — a `CircuitBreaker` is a fixed, referenced object, which is exactly how `CircuitBreakerManager` holds it (`unique_ptr`, handed out by reference).

**Consistency model (important).** Every atomic uses `std::memory_order_relaxed`, and the multi-field transitions are **not** performed as one linearizable step — `allowRequest()`, `recordSuccess()`, and `recordFailure()` each load and store several *independent* atomics. Under concurrency the counters and the state can therefore interleave: two threads racing `recordFailure()` on a `Closed` breaker can both observe the pre-increment count, and a `getStats()` snapshot is field-by-field, not a coherent instant. This is an intentional trade — the breaker is an *approximate*, self-correcting signal, not a transactional accumulator. See §6 and §9.

### 3.2 CircuitBreakerManager

A registry so one process can protect many named dependencies. `mutable std::mutex _mutex` guards `std::unordered_map<std::string, std::unique_ptr<CircuitBreaker>> _breakers`; a `BreakerFactory` (`std::function<std::unique_ptr<CircuitBreaker>()>`) mints new breakers (defaulting to a default-configured `CircuitBreaker`).

```cpp
CircuitBreaker &getBreaker(const std::string &name)
{
  std::lock_guard<std::mutex> lock(_mutex);
  auto it = _breakers.find(name);
  if (it == _breakers.end())
  {
    auto [inserted, success] = _breakers.emplace(name, _factory());
    return *inserted->second;
  }
  return *it->second;
}
```

The convenience methods (`allowRequest(name)`, `recordSuccess(name)`, `recordFailure(name)`, `getState(name)`, `reset(name)`) all route through `getBreaker(name)`, so **naming a dependency for the first time creates its breaker on demand**. `updateAllConfigs()`, `getBreakerNames()`, and `resetAll()` take the mutex and iterate.

**Caveat — the factory runs under the lock.** On a first-touch miss, `getBreaker()` calls `_factory()` **while holding `_mutex`** (`_breakers.emplace(name, _factory())`). A factory that re-enters the same manager self-deadlocks on the non-recursive mutex, and a slow/blocking factory serializes every other named breaker behind it. Supply only a fast, non-re-entrant factory. A double-checked-insert fix (compute the breaker outside the lock, insert under it) is tracked in backlog `2026-09-14-6` (TS-1).

**Why holding the returned reference is safe.** `getBreaker()` returns `CircuitBreaker&` and the caller then uses it *without* the manager lock. That is sound here for two reasons: the `CircuitBreaker` is internally thread-safe (atomics), and **breakers are never erased** — there is no `removeBreaker`. The `unique_ptr` keeps the object at a stable address for the manager's lifetime.

**Factory-only configuration.** A breaker is created with whatever the factory produces; there is no `getBreaker(name, config)` overload. To use a non-default config for a name, either supply a factory that returns pre-configured breakers, or call `updateConfig(name, config)` after first touch.

### 3.3 ConnectionHealth

A lock-free per-connection tracker over five atomics (`_lastActivity`, `_consecutiveFailures`, `_totalSuccesses`, `_totalFailures`, `_state`) plus a plain `_config`.

**State derivation.** `updateState()` maps the *consecutive*-failure count to a level:

```cpp
int failures = _consecutiveFailures.load(std::memory_order_relaxed);
if      (failures == 0)                              newState = ConnectionState::Healthy;
else if (failures == 1)                              newState = ConnectionState::Warning;
else if (failures <  _config.maxConsecutiveFailures) newState = ConnectionState::Degraded;
else if (failures == _config.maxConsecutiveFailures) newState = ConnectionState::Critical;
else                                                 newState = ConnectionState::Unhealthy;
_state.store(newState, std::memory_order_relaxed);
```

Note the boundaries: with the default `maxConsecutiveFailures == 3`, 0 → Healthy, 1 → Warning, 2 → Degraded, 3 → Critical, 4+ → Unhealthy. `isHealthy()` returns true for `state <= Warning` (i.e. Healthy or one stray failure).

**Recording.**
- `recordActivity()` stamps `_lastActivity = now` and, if there were outstanding consecutive failures, resets them to 0 and recomputes state (activity is treated as recovery).
- `recordFailure()` increments `_consecutiveFailures` and `_totalFailures`, then recomputes.
- `recordSuccess()` increments `_totalSuccesses` and, if there are outstanding consecutive failures, *decrements* them by one via a single `compare_exchange_weak` (a gradual recovery), then recomputes. Because the CAS is weak and unlooped, it may fail — including a **spurious** failure with no concurrent writer at all — and simply skip that call's decrement (the next success retries). Treat single-step recovery as best-effort; see §10.

**Time predicates** are computed on demand from `steady_clock::now()`:
- `needsHeartbeat()` — `enableHeartbeat && (now - _lastActivity) >= heartbeatInterval`.
- `isTimedOut()` — `(now - _lastActivity) >= timeoutThreshold` (independent of `enableHeartbeat`).

**Consistency model.** As with `CircuitBreaker`, all atomics are `relaxed` and the counter-then-state updates are not linearizable. The health level is a best-effort rolling signal, not an exact tally. `_totalSuccesses` / `_totalFailures` are monotonic counters and are individually exact.

### 3.4 HealthMonitor

A `SessionId` → `ConnectionHealth` registry: `mutable std::mutex _mutex` guarding `std::unordered_map<SessionId, std::unique_ptr<ConnectionHealth>> _connections`. Every operation that touches the map (`addConnection`, `removeConnection`, the three `record*(id)` forwarders, `getUnhealthyConnections`, `getConnectionsNeedingHeartbeat`, `getOverallStats`, `updateConfig`) takes the mutex for its whole duration, including the call *through* to the child `ConnectionHealth`. `getOverallStats()` walks every entry, bucketing by `ConnectionState` and folding total successes/failures into an aggregate success rate.

Unlike `CircuitBreakerManager`, `HealthMonitor` supports `removeConnection()`, so it never returns a `ConnectionHealth&`/`*` to callers — it always operates on the child under the lock.

`updateConfig()` takes the lock, then updates the monitor's own `_config` member and fans the new config into every existing child under that same lock. Because *every* `HealthMonitor` method that reaches a child also holds `_mutex` for the call-through, a child's `_config` write and all child accesses made **through the monitor** are serialized — race-free on that path. The `ConnectionHealth` `_config` data race (TS-2, backlog `2026-09-14-6`) applies only to a **directly-constructed** standalone `ConnectionHealth` that is reconfigured while other threads call its lock-free methods, not to health tracked via a `HealthMonitor`.

---

## 4. Usage Guide

### Protecting a single downstream service

```cpp
#include "iora/network/circuit_breaker.hpp"
using namespace iora::network;

CircuitBreakerConfig cfg;
cfg.failureThreshold = 10;                 // trip after 10 straight failures, or...
cfg.failureRateThreshold = 0.6;            // ...60% failure rate once...
cfg.minimumRequests = 20;                  // ...at least 20 requests are seen
cfg.timeout = std::chrono::seconds(30);    // stay Open for 30s before probing
cfg.successThreshold = 5;                   // 5 probe successes to fully close

CircuitBreaker breaker{cfg};

bool callWithBreaker()
{
  if (!breaker.allowRequest())
  {
    return false;   // Open and still cooling down: fail fast, do not call
  }
  try
  {
    bool ok = performDownstreamCall();
    if (ok) { breaker.recordSuccess(); }
    else    { breaker.recordFailure(); }
    return ok;
  }
  catch (const std::exception &)
  {
    breaker.recordFailure();
    return false;
  }
}
```

### Many named dependencies via the manager

```cpp
#include "iora/network/circuit_breaker.hpp"
using namespace iora::network;

CircuitBreakerManager manager;   // default factory: default-configured breakers

// First touch of a name creates its breaker on demand.
if (manager.allowRequest("payment-service"))
{
  bool ok = callPayments();
  ok ? manager.recordSuccess("payment-service")
     : manager.recordFailure("payment-service");
}

// Tune one dependency after first touch, or all at once.
CircuitBreakerConfig strict;
strict.failureThreshold = 3;
manager.updateConfig("payment-service", strict);
manager.updateAllConfigs(strict);
```

To have breakers created pre-configured, hand the manager a factory:

```cpp
CircuitBreakerConfig base;
base.timeout = std::chrono::seconds(15);
CircuitBreakerManager manager{[base]() {
  return std::make_unique<CircuitBreaker>(base);
}};
```

### Tracking per-connection health

```cpp
#include "iora/network/connection_health.hpp"
using namespace iora::network;

HealthConfig hcfg;
hcfg.heartbeatInterval = std::chrono::seconds(20);
hcfg.timeoutThreshold  = std::chrono::seconds(60);
hcfg.maxConsecutiveFailures = 4;

HealthMonitor monitor{hcfg};

monitor.addConnection(sessionId);     // SessionId from the transport layer

// On each I/O event for that session:
monitor.recordActivity(sessionId);    // any traffic: treated as recovery
// ...or on an error:
monitor.recordFailure(sessionId);

// Poll on your own cadence (there is no background thread):
for (SessionId id : monitor.getConnectionsNeedingHeartbeat())
{
  sendHeartbeat(id);
}
for (SessionId id : monitor.getUnhealthyConnections())
{
  scheduleReconnect(id);
}

monitor.removeConnection(sessionId);  // on close
```

### Anti-Patterns

- **Do NOT** rely on a background thread to expire the Open state or fire heartbeats — there is none. `allowRequest()` re-probes only when *called* after the timeout, and `needsHeartbeat()`/`getUnhealthyConnections()` reflect health only when *you* poll them.
- **Do NOT** treat HalfOpen as a throttle. It admits **every** request (no probe cap); it does not protect a recovering backend from a thundering herd. If you need at-most-N in-flight probes, gate that yourself.
- **Do NOT** supply a `BreakerFactory` that re-enters the manager or blocks — `getBreaker()` runs it while holding the map mutex, so a re-entrant factory deadlocks and a slow one serializes every breaker.
- **Do NOT** call `CircuitBreaker::updateConfig()` / `ConnectionHealth::updateConfig()` (or `CircuitBreakerManager::updateConfig`/`updateAllConfigs`, which write a breaker's config) concurrently with the record/query methods on the same object. `_config` is a plain member, not an atomic; treat configuration as set-at-construction or quiesced-then-reconfigure. See §6 and §10.
- **Do NOT** expect `getStats()` to be a coherent instant under concurrency — the fields are read from independent relaxed atomics. Use it for monitoring/telemetry, not for a linearizable decision.
- **Do NOT** read `getStats().timeSinceLastFailure` on a breaker that has never failed (or was just `reset()`) as "time since a real failure" — `_lastFailureTime` is the clock epoch there, so the value is huge and meaningless. Gate on `state`/`failureCount` first.
- **Do NOT** treat a `successRate` / `overallSuccessRate` of `1.0` as "healthy" without checking traffic first — an idle `ConnectionHealth` (or an empty/idle `HealthMonitor`) reports `1.0` by default before any success or failure is recorded. Gate on the total success+failure count.
- **Do NOT** assume the transport drives these primitives. Nothing in `Transport`/the engines calls them; an application must record successes/failures itself. (The former dead auto-wire members were removed in iora `7f38bcb`.)

---

## 5. Call Flow / Sequence Reference

### CircuitBreaker: Open → HalfOpen → Closed recovery

| Step | Actor | Action | State after |
|---|---|---|---|
| 1 | Downstream fails repeatedly | `recordFailure()` × N until `shouldOpenCircuit()` | `Open` |
| 2 | Caller | `allowRequest()` before `timeout` elapses → `false` (fail fast) | `Open` |
| 3 | Caller (after `timeout`) | `allowRequest()`: `now - _lastFailureTime >= timeout` → `compare_exchange_strong(Open, HalfOpen)`, reset `_successCount`, return `true` | `HalfOpen` |
| 4 | Caller | probe succeeds → `recordSuccess()`; `_successCount` reaches `successThreshold` → close, zero failure/success counts | `Closed` |
| 4' | Caller (probe fails) | `recordFailure()` in `HalfOpen` → back to `Open`, `_lastFailureTime = now` | `Open` |

### HealthMonitor: recording activity for a session (lock steps explicit)

| Step | Actor | Action |
|---|---|---|
| 1 | Application | `monitor.recordActivity(id)` |
| 2 | HealthMonitor | **acquire `_mutex`** |
| 3 | HealthMonitor | `_connections.find(id)`; if absent, return (no-op) |
| 4 | HealthMonitor | call `it->second->recordActivity()` — lock-free atomics on the child: stamp `_lastActivity`, reset `_consecutiveFailures` if > 0, `updateState()` |
| 5 | HealthMonitor | **release `_mutex`** |

---

## 6. Thread Safety Model

### CircuitBreaker

| Operation | Synchronization | Notes |
|---|---|---|
| `allowRequest`, `recordSuccess`, `recordFailure`, `getState`, `getStats`, `reset` | Lock-free; `std::memory_order_relaxed` on all atomics | Individually atomic; multi-field transitions **not** linearizable (approximate). |
| `updateConfig` | **None** — plain write to `_config` | Data race if concurrent with any request method (TS-2, backlog `2026-09-14-6`). Reconfigure only when quiesced. |

### CircuitBreakerManager

| Operation | Synchronization | Notes |
|---|---|---|
| `getBreaker` and all `*(name)` convenience methods, `getBreakerNames`, `resetAll` | `std::lock_guard<std::mutex> _mutex` over the map | Child breaker then operated lock-free. Returned `CircuitBreaker&` stays valid (breakers never erased). **`getBreaker` runs the user `_factory()` under `_mutex`** (callback-under-lock; TS-1, backlog `2026-09-14-6`) — supply only a fast, non-re-entrant factory. |
| `updateConfig(name)`, `updateAllConfigs` | Locate under `_mutex`, then write the breaker's plain `_config` | Inherits the breaker `updateConfig` data race (TS-2): the manager mutex does not serialize a breaker's lock-free `recordX`/`allowRequest`. Reconfigure only when quiesced. |

### ConnectionHealth

| Operation | Synchronization | Notes |
|---|---|---|
| `recordActivity`, `recordFailure`, `recordSuccess`, `isHealthy`, `getState`, `needsHeartbeat`, `isTimedOut`, `getStats` | Lock-free; `relaxed` atomics | `recordSuccess` decrements via a single `compare_exchange_weak` that may fail spuriously (even without contention), skipping that call's decrement. Not linearizable. |
| `updateConfig` | **None** — plain write to `_config` | Same reconfigure-when-quiesced caveat (TS-2). |

### HealthMonitor

| Operation | Synchronization | Notes |
|---|---|---|
| `addConnection`, `removeConnection`, `recordActivity(id)`, `recordFailure(id)`, `recordSuccess(id)`, `getUnhealthyConnections`, `getConnectionsNeedingHeartbeat`, `getOverallStats`, `updateConfig` | `std::lock_guard<std::mutex> _mutex` for the full operation, including the call through to the child | Never returns a child pointer/reference; safe against concurrent `removeConnection`. Every child access is under `_mutex`, so the through-monitor path (including the `updateConfig` child fan-out) is fully serialized and race-free. The TS-2 `_config` race applies only to a directly-constructed standalone `ConnectionHealth`, not to health tracked through the monitor. |

**Lock ordering.** Each manager holds exactly one leaf mutex and never calls into the other family while holding it, so there is no cross-family lock ordering to observe. The one nested-call caveat is `CircuitBreakerManager::getBreaker` invoking the user `_factory()` under `_mutex` (above) — the manager does not lock any *other* Iora mutex while holding `_mutex`, but a user factory could.

---

## 7. Configuration Reference

### CircuitBreakerConfig

| Field | Type | Default | Meaning |
|---|---|---|---|
| `failureThreshold` | `int` | `5` | Absolute consecutive-failure count that trips the circuit Open (checked first; in practice the dominant trigger). |
| `timeout` | `std::chrono::seconds` | `60` | Cooldown in Open before `allowRequest()` promotes to a HalfOpen probe. |
| `successThreshold` | `int` | `3` | Probe successes required in HalfOpen to close the circuit. |
| `statisticsWindow` | `std::chrono::seconds` | `300` | **Not consumed by the current implementation** — see §10. The failure *rate* is computed over lifetime `_requestCount`, not a sliding window. |
| `failureRateThreshold` | `double` | `0.5` | Failure rate (0.0–1.0) that trips Open once `minimumRequests` is reached. See §3.1 — the numerator resets on each success while the denominator is lifetime, so this rule rarely fires before `failureThreshold`. |
| `minimumRequests` | `int` | `10` | Minimum lifetime request count before the failure-rate rule is considered. |

### HealthConfig

| Field | Type | Default | Meaning |
|---|---|---|---|
| `heartbeatInterval` | `std::chrono::seconds` | `30` | Idle span after which `needsHeartbeat()` returns true (when `enableHeartbeat`). |
| `timeoutThreshold` | `std::chrono::seconds` | `90` | Idle span after which `isTimedOut()` returns true (independent of `enableHeartbeat`). |
| `maxConsecutiveFailures` | `int` | `3` | Consecutive-failure count mapped to `Critical`; one more maps to `Unhealthy`. |
| `enableHeartbeat` | `bool` | `true` | When false, `needsHeartbeat()` is always false. |

---

## 8. API Reference

```cpp
namespace iora { namespace network {

struct CircuitBreakerConfig
{
  int failureThreshold{5};
  std::chrono::seconds timeout{60};
  int successThreshold{3};
  std::chrono::seconds statisticsWindow{300};
  double failureRateThreshold{0.5};
  int minimumRequests{10};
};

enum class CircuitBreakerState { Closed, Open, HalfOpen };

class CircuitBreaker
{
public:
  explicit CircuitBreaker(const CircuitBreakerConfig &config = {});
  bool allowRequest();
  void recordSuccess();
  void recordFailure();
  CircuitBreakerState getState() const;
  struct Stats
  {
    CircuitBreakerState state;
    int failureCount;
    int successCount;
    std::uint64_t totalRequests;
    std::chrono::milliseconds timeSinceLastFailure;
    double failureRate;
  };
  Stats getStats() const;
  void updateConfig(const CircuitBreakerConfig &config);
  void reset();
};

class CircuitBreakerManager
{
public:
  using BreakerFactory = std::function<std::unique_ptr<CircuitBreaker>()>;
  explicit CircuitBreakerManager(BreakerFactory factory = nullptr);
  CircuitBreaker &getBreaker(const std::string &name);
  bool allowRequest(const std::string &name);
  void recordSuccess(const std::string &name);
  void recordFailure(const std::string &name);
  CircuitBreakerState getState(const std::string &name);
  void updateConfig(const std::string &name, const CircuitBreakerConfig &config);
  void updateAllConfigs(const CircuitBreakerConfig &config);
  std::vector<std::string> getBreakerNames() const;
  void reset(const std::string &name);
  void resetAll();
};

struct HealthConfig
{
  std::chrono::seconds heartbeatInterval{30};
  std::chrono::seconds timeoutThreshold{90};
  int maxConsecutiveFailures{3};
  bool enableHeartbeat{true};
};

enum class ConnectionState { Healthy, Warning, Degraded, Critical, Unhealthy };

class ConnectionHealth
{
public:
  explicit ConnectionHealth(const HealthConfig &config = {});
  void recordActivity();
  void recordFailure();
  void recordSuccess();
  bool isHealthy() const;
  ConnectionState getState() const;
  bool needsHeartbeat() const;
  bool isTimedOut() const;
  struct Stats
  {
    ConnectionState state;
    int consecutiveFailures;
    std::uint64_t totalSuccesses;
    std::uint64_t totalFailures;
    std::chrono::milliseconds timeSinceLastActivity;
    double successRate;
  };
  Stats getStats() const;
  void updateConfig(const HealthConfig &config);
};

class HealthMonitor
{
public:
  explicit HealthMonitor(const HealthConfig &config = {});
  void addConnection(SessionId id);
  void removeConnection(SessionId id);
  void recordActivity(SessionId id);
  void recordFailure(SessionId id);
  void recordSuccess(SessionId id);
  std::vector<SessionId> getUnhealthyConnections() const;
  std::vector<SessionId> getConnectionsNeedingHeartbeat() const;
  struct OverallStats
  {
    std::size_t totalConnections;
    std::size_t healthyConnections;
    std::size_t warningConnections;
    std::size_t degradedConnections;
    std::size_t criticalConnections;
    std::size_t unhealthyConnections;
    double overallSuccessRate;
  };
  OverallStats getOverallStats() const;
  void updateConfig(const HealthConfig &config);
};

}} // namespace iora::network
```

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Two independent primitives, not one "resilience manager" | They answer different questions at different layers (generic dependency health vs. per-`SessionId` connection health) and share no state; fusing them would couple a generic breaker to the transport's `SessionId`. |
| Lock-free primitives, mutex-guarded registries | The hot path (record/query one breaker or one connection) must be cheap and contention-free; only the map structure needs mutual exclusion. |
| Lock-free enum transitions rather than `iora::core::StateMachine` | `StateMachine` is the project's canonical FSM primitive, but its thread-safety model is mutex-protected transitions — incompatible with the lock-free hot-path requirement above (adopting it would make `allowRequest`/`record*`/`updateState` blocking). The hand-rolled atomic transitions here are a deliberate, informed rejection of `iora::core::StateMachine` for these primitives, not an oversight; revisit only if the lock-free requirement is relaxed. |
| `relaxed` atomics, non-linearizable transitions accepted | A breaker/health signal is inherently statistical; the cost of making every transition linearizable (a lock or a CAS loop over a composite state) buys accuracy the use case does not need. |
| Breaker trips on count **or** rate | An absolute count catches a hard-down dependency quickly; a rate is a secondary guard, though (see §3.1) its current numerator/denominator time-base makes the count the dominant trigger. |
| `CircuitBreakerManager` has no removal API | Making breakers permanent is what lets `getBreaker()` return a bare reference the caller can keep and use lock-free. |
| No background thread; time is computed lazily | Keeps the primitives allocation- and thread-free; the owning application already has a poll/event loop and decides the cadence for heartbeats and Open re-probes. |
| HalfOpen admits all requests (no probe cap) | Keeps the state machine lock-free and counter-only; per-service probe throttling is left to the caller, which knows its own concurrency budget. |
| Transport does **not** auto-wire either primitive | The former auto-wire members were dead since introduction and were removed (iora `7f38bcb`); these are offered as standalone, application-composed primitives. Documenting them as wired would be fabrication. |

---

## 10. Known Limitations

| Limitation | Impact |
|---|---|
| **HalfOpen has no probe cap.** | `allowRequest()` returns `true` for every caller in HalfOpen; a recovering backend receives the full request volume, not a throttled trickle. The caller must throttle probes if it needs to. |
| **`statisticsWindow` is unused, and the failure-rate rule is weak.** | `CircuitBreakerConfig::statisticsWindow` is declared but never read; the failure rate is `_failureCount / _requestCount` where the numerator is reset by any success and the denominator is lifetime — so the rate rule seldom trips before `failureThreshold`, and old failures never "age out" except via `reset()`. |
| **No transport integration.** | Neither primitive is driven by the transport/engines; an application must call `recordSuccess`/`recordFailure`/`recordActivity` itself. The former dead auto-wire members and the no-op `autoHealthMonitoring` flag were removed (iora `7f38bcb`). |
| **No background expiry or heartbeat delivery.** | Open→HalfOpen promotion happens only on the next `allowRequest()` after the timeout; heartbeat-due and unhealthy sets reflect reality only when polled. No timer is owned. |
| **`getStats().timeSinceLastFailure` is meaningless before the first failure.** | `_lastFailureTime` is initialized to (and `reset()` restores) the `steady_clock` epoch, so `getStats()` reports `now - epoch` (roughly machine uptime) for a breaker that has never failed. Gate telemetry on `state`/`failureCount` first. |
| **Idle success rate reads as `1.0`.** | `ConnectionHealth::getStats().successRate` and `HealthMonitor::getOverallStats().overallSuccessRate` return `1.0` when no traffic has been recorded (a fresh connection is also `ConnectionState::Healthy`). Telemetry sampled before any I/O sees a misleadingly perfect rate; gate on the total success+failure count. |
| **`updateConfig` is not concurrency-safe (TS-2, backlog `2026-09-14-6`).** | `_config` is a plain member on `CircuitBreaker`/`ConnectionHealth` (and written via the manager's `updateConfig`/`updateAllConfigs`); it races any concurrent record/query. Reconfigure only when the object is quiesced. |
| **`getBreaker` runs the factory under the map lock (TS-1, backlog `2026-09-14-6`).** | A re-entrant `BreakerFactory` self-deadlocks and a slow one serializes all breakers. Use a fast, non-re-entrant factory pending the double-checked-insert fix. |
| **Non-linearizable snapshots and transitions.** | `getStats()` is field-by-field across independent relaxed atomics; concurrent record calls can interleave counter and state updates. The signals are approximate by design. |
| **`ConnectionHealth::recordSuccess` recovery may stall one step (TS-4, backlog `2026-09-14-6`).** | The single `compare_exchange_weak` decrement can fail spuriously (even without contention), skipping that call's recovery decrement (the next success retries). |
