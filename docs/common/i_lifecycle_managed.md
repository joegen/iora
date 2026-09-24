# Iora ILifecycleManaged -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-24 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/common/i_lifecycle_managed.hpp` |
| **Namespace** | `iora::common` |
| **Dependencies** | `<cstdint>`, `<optional>`, `<string>` (standard library only) |

This guide covers `iora::common::ILifecycleManaged`, the abstract interface for components that support graceful drain, stop, and restart, together with its value types `LifecycleState`, `DrainStats`, `LifecycleResult` and the helper `lifecycleStateToString`. The two in-tree implementers are `iora::core::ThreadPool` (the alias `using ThreadPool = ThreadPoolT<false>`, `core/thread_pool.hpp:1287`; class template at `:72-73`; see [`../core/thread_pool.md`](../core/thread_pool.md)) and `iora::core::TimerService` (`core/timer.hpp:282`, see [`../core/timer.md`](../core/timer.md)). Downstream, iora_sip implements it in several layers (for example `TransactionManager`, `SipTimingWheelAdapter`, `TimerServiceAdapter`, `RegistrationManagerLifecycleWrapper`).

**Document scope.** This guide uses the sanctioned lite variant of the Architecture & Programmer's Guide template: the header is a pure interface plus three plain value types, with no implementation, no configuration, and no threading of its own, so System Architecture, Call Flow, and Configuration Reference do not apply. The behavior of each transition lives in the implementers' guides; this guide states the contract and where the implementers differ.

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-24 | Initial guide, authored against source. Header comments corrected in the same change: `start()` restarts from `Reset` directly to `Running` (no transition back to `Created`); `stop()` is valid from `Running` or `Draining`; the state after a drain timeout is implementer-defined; the in-flight definitions now describe what each implementer actually counts; the iora_sip-specific examples (SIP CANCEL/500, Transaction Layer) were replaced with layer-neutral wording. `lifecycleStateToString` is now `noexcept`. Implementer defects found while writing this guide are tracked in coding_trackers `tasks/iora/backlog/2026-09-24-5_timerservice-concurrent-lifecycle-transitions_P0.json`, `2026-09-24-6_threadpool-lifecycle-gaps_P0.json` and `2026-09-24-7_lifecycle-state-single-source-enumerators_P1.json`. |

---

## Executive Summary

**Problem.** Components that own threads or queued work (a thread pool, a timer service, a transaction layer) need a common way to be shut down without losing in-flight work, and then either destroyed or restarted. Without a shared contract every component invents its own `shutdown()`/`close()`/`join()` with different blocking and idempotency semantics, and a higher layer cannot drain its dependencies uniformly.

**Solution.**
- `LifecycleState` -- `Created`, `Running`, `Draining`, `Stopped`, `Reset` (`i_lifecycle_managed.hpp:20-27`).
- `ILifecycleManaged` -- six pure virtuals: `start()`, `drain(timeoutMs = 30000)`, `stop()`, `reset()`, `getState() const`, `getInFlightCount() const` (`:66-163`).
- `LifecycleResult` -- `success`, `newState`, `message`, and an optional `DrainStats` for drain operations (`:46-64`).
- `DrainStats` -- `inFlightAtStart`, `remaining`, `cancelled`, `completed` (`:30-43`).
- `lifecycleStateToString(LifecycleState)` -- the state name as a `const char *` (`:166-183`).

**Technical impact.** The interface has no data and no behavior; a component opts in by inheriting it. Transitions report outcome through `LifecycleResult` rather than exceptions (the header still permits `start()` to throw, and both implementers can; see the API table), so a caller can drain a set of components and collect per-component statistics.

---

## Deep Dive & Usage

### The state machine

```
            start()           drain(t)              stop()             reset()
 Created ----------> Running ----------> Draining ----------> Stopped ----------> Reset
                        ^                                                          |
                        +--------------------------- start() ----------------------+
```

The header states the contract (`i_lifecycle_managed.hpp:66-78` and the per-method comments): `drain()` stops accepting new work and blocks until in-flight work completes or the timeout expires; `stop()` from `Running` first drains the component's own work (a composite also drains its dependencies), then exits event loops, but does not release resources; `reset()` releases resources and clears state so `start()` can run again. The diagram is the intended path; `stop()` is also accepted directly from `Running`.

**`Draining` is one-way.** Neither implementer accepts `start()` or `drain()` from `Draining`, so `drain()` is not a pause: after a drain the way back to accepting work is `stop()` -> `reset()` -> `start()`. (A `TimerService` whose drain *times out* returns to `Running` by itself; see the table.)

### How the implementers realize it

The interface does not enforce transitions; each implementer guards its own. Verified against source:

| Aspect | `ThreadPool` | `TimerService` |
|---|---|---|
| State after construction | `Running` (the constructor starts workers, `thread_pool.hpp:183`) | `Running` (the constructor calls `initialize()`, which sets `Running`, `timer.hpp:1096`) |
| `start()` from `Running` or `Created` | success, "Already running" (`:421-438`) | success, "Already running" (`timer.hpp:630-646`) |
| `start()` from `Reset` | restarts to `Running` (`:440-455`) | restarts to `Running` (`:648-652`) |
| `drain()` valid from | `Running` only (`:483`) | `Running` only (CAS, `:681`) |
| `drain(0)` | waits up to **one hour** (`:500`) | waits with no deadline (`:805-807`) |
| State after a drain **timeout** | stays `Draining`, `success == false` (`:515`); `drain()` cannot be retried from `Draining` (`:483`) | back to `Running` (CAS `Draining -> Running`, `:850-859`) if the run loop had not exited when the timeout was observed and no concurrent `stop()` moved the state on; otherwise it stays where it is |
| `stop()` valid from | `Running` or `Draining` (`:543`) | anything except `Stopped`/`Reset` (`:888`) |
| `stop()` from `Running` | drains first with a fixed **30 s** budget (`:555`) | drains first with a fixed **5 s** budget (`:897`) |
| `stop()` from `Draining` | **no wait**: if anything is still in flight it force-detaches immediately (`:552-576`) | proceeds to stop |
| `stop()` when work is still in flight | force-detaches the workers and returns `success == false`, `Stopped`; the pool is then **terminally detached**: `start()`, `stop()` and `reset()` refuse from then on (`:562-576`, `refuseIfDetached` `:708`) | proceeds (from `Running`, after logging a warning that its drain failed) to join its run-loop thread, which waits for any executing callback **without a bound**; the loop's final pass still fires timers already due, and timers not yet due are abandoned; returns `success == true` (`:895-920`) |
| Resources after `stop()` | kept (released by `reset()`) | **released**: `stop()` calls `cleanup()`, which closes its epoll/timer/event fds (`:916`, `:1130-1147`) -- contrary to the contract |
| `reset()` valid from | `Stopped` only (`:603`); refused if terminally detached | `Stopped` only (`:938`) |

In practice `Created` is never observed on either implementer: both constructors go straight to `Running`. `getState()` reads an atomic and `getInFlightCount()` is a snapshot taken under the component's mutex (ThreadPool: queued + busy tasks, `thread_pool.hpp:650-655`; TimerService: non-cancelled timer records, `timer.hpp:971-992`), both safe to call from any thread while a transition is in progress.

### `DrainStats` semantics

`inFlightAtStart` is the `getInFlightCount()` snapshot when the drain began; `remaining` is the count still in flight when it returned; `cancelled` counts work the drain deliberately cancelled (the timer service cancels periodic and far-future one-shot timers; the thread pool never cancels, so it reports `0`); `completed` is what finished normally. In both implementers `LifecycleResult::drainStats` is set only by `drain()` (`thread_pool.hpp:511`, `timer.hpp:838`); `stop()` results carry no stats, even when `stop()` drains internally.

### Usage

**1. Drain then stop a component, with a bounded wait.** What a timed-out `drain()` leads to differs: on `ThreadPool` the following `stop()` gives no extra grace from `Draining` and force-detaches the pool for good if work is still in flight, so pick a drain timeout long enough for the work (or skip `drain()` and let `stop()` apply its own 30 s budget); on `TimerService` the timed-out drain returns to `Running` and `stop()` then drains again for up to 5 s.

```cpp
#include <iora/common/i_lifecycle_managed.hpp>

#include <cstdint>
#include <iostream>

void shutdown(iora::common::ILifecycleManaged &c)
{
  using iora::common::lifecycleStateToString;

  const auto drained = c.drain(5000);
  if (!drained.success && drained.drainStats)
  {
    std::cerr << "drain timed out, " << drained.drainStats->remaining << " still in flight\n";
  }
  const auto stopped = c.stop();
  std::cerr << "state: " << lifecycleStateToString(stopped.newState) << '\n';
}
```

**2. Restart after a full shutdown.** Works from `Running`, `Draining`, `Stopped` or `Reset`. On `ThreadPool` it fails if an earlier `stop()` had to force-detach its workers (the pool is then terminally detached).

```cpp
#include <iora/common/i_lifecycle_managed.hpp>

bool restart(iora::common::ILifecycleManaged &c)
{
  using iora::common::LifecycleState;
  const LifecycleState state = c.getState();
  if (state != LifecycleState::Reset)
  {
    if (state != LifecycleState::Stopped && !c.stop().success)
    {
      return false;
    }
    if (!c.reset().success)
    {
      return false;
    }
  }
  return c.start().success; // Reset -> Running
}
```

**3. A minimal implementer.** An illustration of the interface shape only: it guards no preconditions, whereas a real implementer must check the current state in each transition (for example `reset()` only from `Stopped`).

```cpp
#include <iora/common/i_lifecycle_managed.hpp>

#include <atomic>
#include <cstdint>

class Worker : public iora::common::ILifecycleManaged
{
public:
  using State = iora::common::LifecycleState;
  using Result = iora::common::LifecycleResult;

  Result start() override
  {
    _state = State::Running;
    return Result(true, State::Running, "started");
  }
  Result drain(std::uint32_t timeoutMs = 30000) override
  {
    (void)timeoutMs;
    _state = State::Draining;
    return Result(true, State::Draining, "drained", iora::common::DrainStats(0, 0, 0, 0));
  }
  Result stop() override
  {
    _state = State::Stopped;
    return Result(true, State::Stopped, "stopped");
  }
  Result reset() override
  {
    _state = State::Reset;
    return Result(true, State::Reset, "reset");
  }
  State getState() const override
  {
    return _state.load();
  }
  std::uint32_t getInFlightCount() const override
  {
    return 0;
  }

private:
  std::atomic<State> _state{State::Created};
};
```

**Anti-patterns.**
- Do NOT assume `drain(0)` is unbounded on every implementer; `ThreadPool` caps it at one hour. Pass an explicit timeout when the bound matters.
- Do NOT assume a timed-out `drain()` leaves the component in `Draining`; `TimerService` normally returns to `Running` and keeps accepting work. Read `newState`.
- Do NOT call a transition -- or `ThreadPool::shutdown()`, or drop the component's last owner -- from the component's own thread (a `ThreadPool` task, a `TimerService` callback). Both implementers then wait on, or join, the calling thread itself: outcomes range from a 30 s / 5 s stall to a forced detach, a permanent `drain(0)` deadlock, or `std::terminate`. See "Known implementer gaps" below.
- Do NOT call transitions of one component concurrently from several threads unless its guide says they are serialized: `ThreadPool` serializes them (but not against `shutdown()`), `TimerService` does not. See the Thread Safety Model.
- Do NOT treat a failed `LifecycleResult` as an exception-free "no-op": read `newState`, which reports the state the component is actually in (for example `drain()` from the wrong state returns `success == false` with the unchanged current state).
- Do NOT declare a different default for `drain`'s `timeoutMs` in an override. Default arguments on virtual functions bind to the static type, so `base.drain()` and `derived.drain()` would use different values. Both in-tree implementers repeat `30000`.
- Do NOT call `reset()` expecting it to stop a running component; both implementers reject it unless the state is `Stopped`.

---

## Thread Safety Model

The header itself has no state and no synchronization. The contract comment says "all methods are thread-safe unless documented otherwise" (`i_lifecycle_managed.hpp:78`): it is the implementer's obligation. `getState()` and `getInFlightCount()` are safe from any thread on both implementers (an atomic load, and a snapshot under the component's mutex). The transitions differ:

- **ThreadPool** serializes `start`/`drain`/`stop`/`reset` under `_lifecycleMutex` (lock order `_lifecycleMutex -> _mutex`), so a transition blocks while another is in progress: a `stop()` meant to abort a stuck `drain()` waits until that drain returns (up to its timeout, one hour for `0`). The public `ThreadPool::shutdown()` and the destructor are **not** part of that serialization. Do not call `shutdown()` concurrently with another `shutdown()`, the destructor, or a transition: a `shutdown()` that returns because shutdown is already in progress does not mean the workers have exited (TP-6).
- **TimerService** has no lifecycle mutex. Only `drain()` gates its state change on a compare-and-swap (`timer.hpp:681`); `stop()`'s compare-and-swap on `_running` (`:906`) merely picks which caller joins and cleans up, and a losing concurrent `stop()` reports `Stopped` before that teardown has finished (TS-2); `start()` and `reset()` are unguarded (TS-1). Concurrent transitions are therefore **not** safe today: call its transitions from one thread. Its `stop()` and destructor join the run-loop thread without a bound (TS-8).
- **ThreadPool's `stop()` normally force-detaches rather than hanging, but it is not strictly bounded:** it first waits for any transition in progress (up to an hour behind `drain(0)`), and a task admitted after its drain (TP-9) is joined without a bound. Its destructor and `shutdown()` join without a bound when a task is stuck (in `IMMEDIATE` mode; `DETACHED` mode detaches). After a forced detach the destructor does **not** wait for the detached workers, which still reference the pool: destroying the pool while a stuck task is still running is undefined behavior (see [`../core/thread_pool.md`](../core/thread_pool.md); tracked in `tasks/iora/backlog/2026-09-10-8_threadpool-detached-worker-shared-control-block-teardown_P2.json`). Keep such a pool alive.

`LifecycleResult` and `DrainStats` are plain value types returned by copy, so a result can be passed between threads freely.

---

## API Reference

```cpp
namespace iora
{
namespace common
{

enum class LifecycleState
{
  Created,
  Running,
  Draining,
  Stopped,
  Reset
};

struct DrainStats
{
  std::uint32_t inFlightAtStart;
  std::uint32_t remaining;
  std::uint32_t cancelled;
  std::uint32_t completed;

  DrainStats();
  DrainStats(std::uint32_t inFlight, std::uint32_t rem, std::uint32_t canc, std::uint32_t comp);
};

struct LifecycleResult
{
  bool success;
  LifecycleState newState;
  std::string message;
  std::optional<DrainStats> drainStats;

  LifecycleResult();
  LifecycleResult(bool succ, LifecycleState state, const std::string &msg);
  LifecycleResult(bool succ, LifecycleState state, const std::string &msg, const DrainStats &stats);
};

class ILifecycleManaged
{
public:
  virtual ~ILifecycleManaged() = default;
  virtual LifecycleResult start() = 0;
  virtual LifecycleResult drain(std::uint32_t timeoutMs = 30000) = 0;
  virtual LifecycleResult stop() = 0;
  virtual LifecycleResult reset() = 0;
  virtual LifecycleState getState() const = 0;
  virtual std::uint32_t getInFlightCount() const = 0;
};

inline const char *lifecycleStateToString(LifecycleState state) noexcept;

} // namespace common
} // namespace iora
```

| Member | Notes |
|---|---|
| `start()` | `Created`/`Reset` -> `Running`; may throw: `ThreadPool` on a worker-spawn failure, `TimerService` on a thread-creation `std::system_error` (it returns a failed result for its own `TimerException`) |
| `drain(timeoutMs)` | `Running` -> `Draining`; blocks; `0` = no timeout per the contract (ThreadPool caps at one hour); state after a timeout is implementer-defined |
| `stop()` | `Running`/`Draining` -> `Stopped`; exits loops/threads; keeps resources per the contract (TimerService releases its fds) |
| `reset()` | `Stopped` -> `Reset`; releases resources |
| `getState()` | current state; thread-safe |
| `getInFlightCount()` | component-defined in-flight count (ThreadPool: queued + busy tasks; TimerService: non-cancelled timer records, not counting executing callbacks) |
| `LifecycleResult()` | `success = false`, `newState = Created`, empty message, no stats |
| `DrainStats()` | all counts `0` |
| `lifecycleStateToString` | `"Created"`, `"Running"`, `"Draining"`, `"Stopped"`, `"Reset"`, or `"Unknown"` for an out-of-range value |

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Result objects, not exceptions, for transitions | Shutdown code drains many components in sequence; a failure in one must not skip the rest, and the caller wants per-component counts. |
| Separate `drain` / `stop` / `reset` | Distinguishes "finish what you have" (drain), "stop running" (stop), and "free everything" (reset), so a supervisor can stop a component yet keep its resources for inspection, or restart it without reconstruction. (`TimerService` does not yet honor the keep-resources half; TS-3.) |
| `drain` blocks with a timeout | Callers need a bounded shutdown; the default 30 s matches typical process-manager stop grace periods. |
| `DrainStats` inside `std::optional` | Only drain-type operations have counts; the other transitions leave it empty rather than reporting zeros. |
| Restart goes `Reset` -> `Running` directly | Both implementers restart from `Reset`; a separate `Created` step would add a transition nobody calls. |
| Enumerator names kept in PascalCase | `Created` / `Running` / `Draining` / `Stopped` / `Reset` predate the ALL_UPPERCASE enum-value rule and are part of a cross-repo interface (iora_sip implements it in several layers); renaming them would break every implementer. Waived on 2026-09-24. |

---

## Known Limitations

- **The state machine is not enforced by the interface.** Each implementer checks its own preconditions and outcomes, and they differ (see the implementer table).
- **Known implementer gaps.** The implementers do not fully meet this contract today. The defects are tracked, and the implementer guides ([`../core/thread_pool.md`](../core/thread_pool.md), [`../core/timer.md`](../core/timer.md)) own their details:
  - ThreadPool -- `tasks/iora/backlog/2026-09-24-6_threadpool-lifecycle-gaps_P0.json` (TP-1..TP-11): transitions, `shutdown()` or destruction from its own task (self-wait, forced detach, `std::terminate`); `shutdown()` not serialized with the transitions; a task admitted after a successful `drain()`; no grace for `stop()` from `Draining`; `drain(0)` capped at one hour and a sleep-summed budget; `timeoutMs` narrowed to `int`; spawn failures during construction or restart.
  - TimerService -- `tasks/iora/backlog/2026-09-24-5_timerservice-concurrent-lifecycle-transitions_P0.json` (TS-1..TS-9) and `tasks/iora/ongoing/2026-09-13-5_timerservice-stop-join-on-self_P0.json`: concurrent transitions; `stop()` releasing resources; `drain(0)` from a callback deadlocking; `stop()` or destruction from a callback self-joining; fd leaks on `initialize()` failures; `reset()` recycling timer IDs; the unbounded join in `stop()`; a drain-timeout restore that is not atomic with the run-loop-exit check.
- **ThreadPool can become terminally detached.** A `stop()` that cannot quiesce force-detaches its workers; the pool can never be restarted (`thread_pool.hpp:562-576`, `:708`), and it must not be destroyed while the detached task is still running (undefined behavior; see the Thread Safety Model).
- **Naming.** `LifecycleState::Reset` is named after the action that produces it ("has been reset"), and `LifecycleResult::newState` is the *current* state even when the transition failed and nothing changed.
- **`Created` is effectively unused.** Both implementers are `Running` on construction, so a caller cannot construct-then-start.
- **Counts are 32-bit.** `DrainStats` fields and `getInFlightCount()` are `std::uint32_t`; ThreadPool saturates a larger count to the 32-bit maximum.
- **No dependency orchestration helper.** The contract describes `stop()` draining dependencies, but there is no registry or helper that walks a dependency graph; each component does it by hand.
- **No dedicated test file for the header.** The contract is exercised through `tests/core/iora_test_threadpool_lifecycle.cpp` and `tests/core/iora_test_timer_lifecycle.cpp`; `lifecycleStateToString` (all five names and the `"Unknown"` fallback) is tested in the former. That test lists the states by hand and the function's `switch` has a `default`, so a future sixth state would escape both (tracked in `tasks/iora/backlog/2026-09-24-7_lifecycle-state-single-source-enumerators_P1.json`).

---

*See also:* [`../core/thread_pool.md`](../core/thread_pool.md) and [`../core/timer.md`](../core/timer.md) (the two implementers).
