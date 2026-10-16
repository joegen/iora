# Iora Callback Ownership (`CallbackOwner` / `CallbackGate`) -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-10-17 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/core/callback_ownership.hpp` (definitions of the single instances in `src/core/iora_core.cpp`) |
| **Namespace** | `iora::core` |
| **Dependencies** | Standard library only -- `<condition_variable>`, `<cstddef>`, `<mutex>`, `<set>`, `<string>`, `<unordered_map>`, `<utility>`. |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-10-17 | Initial guide (tracker 2026-10-16-12, `architecture/iora/plugin_callback_ownership.json`). Written against `include/iora/core/callback_ownership.hpp`, its users `EventQueue` and `HttpServer`, the `IoraService` lifecycle wiring, and the tests `tests/core/iora_test_callback_ownership.cpp` (U-1..U-8), `tests/core/iora_test_event_queue.cpp` (E-1..E-8), `tests/network/iora_test_http_server_owner_removal.cpp` (H-1..H-7) and `tests/service/iora_test_plugin_callback_lifecycle.cpp` (P-1..P-14). |

---

## 1. Executive Summary

### Problem

A plugin registers webhook routes and EventQueue handlers, usually in `onLoad`. Each one is a `std::function` whose code lives in the plugin's `.so` and usually captures the plugin's `this`. Before this component, nothing removed them when the plugin was unloaded, reloaded or failed to load: `EventQueue::onEventId` / `onEventName` / `onEventNameMatches` only appended, and `HttpServer` had no removal API. After `dlclose`, a worker that dispatched the event or served the route called into unmapped code through a destroyed object -- a crash or a use-after-free. A reload also registered every handler a second time.

### Solution

- **`CallbackOwner`** names the owner of callbacks registered on the current thread. `CallbackOwner::Scope(owner)` sets it for a block; `CallbackOwner::current()` reads it. `IoraService` opens a scope around every plugin hook, so plugins need no code change.
- **`CallbackGate`** gates the invocation of owned callbacks per owner. A registry calls `CallbackGate::admit(owner)` before it copies an owned callback; the returned `Admission` is released after the copy is destroyed. The owner's lifecycle side calls `close` (later admits fail), `drain` (wait until no admission is alive) and `open`.
- **`EventQueue` and `HttpServer`** store the owner with each entry when the instance is opted in with `enableCallbackOwnerTracking()`, skip (EventQueue) or answer 503 (HttpServer) for a closed owner, and remove all of an owner's entries with `removeHandlersOwnedBy(owner)`.
- **`IoraService`** opts in its own event queue and webhook server, closes a plugin before its factory runs and opens it when the load commits, and on unload closes, drains and removes the plugin's callbacks before its `.so` is unloaded.

### Technical Impact

- `admit` of an unowned callback (empty owner) takes no lock and does no accounting, so code that does not use owners pays one string `empty()` check per dispatch.
- `admit` of an owned callback is one leaf-mutex lock, one hash lookup and one thread-local multiset insert.
- `drain` waits only for the admissions of one owner; an EventQueue dispatch releases each admission right after its own handler.
- One `thread_local` record and one gate per process, even across plugins loaded `RTLD_LOCAL`.

---

## 2. System Architecture

### 2.1 Component relationships

```
iora::core::detail::CallbackThreadState      (one per thread, defined once in iora_core.cpp)
  ├── std::string owner                      <- CallbackOwner::current(), set by Scope
  └── std::multiset<std::string> admitted    <- owners this thread holds an Admission of

iora::core::CallbackGate
  └── Gate (immortal, defined once in iora_core.cpp)
        ├── std::mutex mutex                 (LEAF)
        ├── std::condition_variable drained
        └── unordered_map<owner, OwnerState{ size_t inFlight; bool closed; }>

EventQueue / HttpServer (opted in)           IoraService
  ├── entries carry `owner`                    ├── Scope(module) around factory/onLoad/
  ├── dispatch: admit -> copy -> invoke         │   onDependency*/onUnload
  │   -> destroy copy -> release                ├── close at load start / unload claim
  └── removeHandlersOwnedBy(owner)              ├── drain in the unload release window
                                                ├── removeModuleCallbacksLocked before erase/dlclose
                                                └── open after the load commits / in openGate
```

### 2.2 Data flow -- unload with a handler in flight

```mermaid
sequenceDiagram
    participant W as EventQueue worker
    participant G as CallbackGate
    participant U as unloadSingleModule
    W->>G: admit("m.so") (inFlight=1)
    W->>W: invoke handler (plugin code)
    U->>G: close("m.so") (claim, under _loadModulesMutex)
    U->>G: drain("m.so") (lock released; waits)
    W->>W: destroy handler copy
    W->>G: Admission release (inFlight=0, notify_all)
    G-->>U: drain returns
    U->>U: onUnload; removeModuleCallbacksLocked; erase; dlclose
    U->>G: open("m.so") (openGate)
```

### 2.3 Threading model

| Thread | Responsibility |
|---|---|
| Registering thread (a plugin hook under `IoraService`) | Holds a `CallbackOwner::Scope`; registrations on an opted-in registry store its owner. |
| Dispatching thread (EventQueue worker, HttpServer pool worker) | Creates, releases and destroys each `Admission` on its own stack. |
| Owner-lifecycle thread (the loader / unloader) | Calls `close` / `open` under `_loadModulesMutex`; calls `drain` with no lock held. |

---

## 3. Component Deep Dive

### 3.1 `CallbackOwner`

`current()` returns `detail::callbackThreadState().owner`. `Scope(std::string owner)` swaps `owner` into the thread state and keeps the previous value; the destructor swaps it back, so scopes nest and restore in order. Both are `noexcept`: the by-value argument is built at the call site, so a `bad_alloc` happens before the scope exists. `Scope("")` makes registrations in its block unowned.

### 3.2 `CallbackGate::admit` and `Admission`

`admit("")` returns an admitted `Admission` with no accounting and no lock. For a non-empty owner it has the strong guarantee:

1. insert the owner into this thread's `admitted` multiset;
2. lock the gate mutex and find-or-create the owner state;
3. if the owner is closed: erase the multiset entry and return a not-admitted result;
4. else `++inFlight` and return an admitted result.

A throw in step 2 erases the step-1 entry and propagates. `Admission` is move-only. Its destructor and its move assignment (over a counted admission) release it: erase **one** occurrence of the owner from this thread's multiset (`find` + `end()` check, never `erase(key)`), then `leave(owner)`. A moved-from `Admission` releases nothing; self-move does nothing.

**Same-thread rule.** An `Admission` must be released on the thread that created it, because the multiset is thread-local. `EventQueue` and `HttpServer` create, release and destroy each one on one worker stack.

### 3.3 `leave`, `close`, `drain`, `open`

- `leave` (private): lock; find the owner (never `operator[]`); `--inFlight`; at zero, `notify_all` **under the lock** (a drain waiter may go on to `dlclose`), then erase the state if the owner is not closed. The notify does not depend on `closed`: a drain of an open owner must wake too.
- `close(owner)`: lock; `owners[owner].closed = true`. No-op for `""`.
- `drain(owner)`: wait on `drained` until the owner has no state or `inFlight == 0`. The predicate calls `owners.find(owner)` on every evaluation and holds no iterator across the wait, because `leave` may erase the state of an open owner while `drain` waits. No-op for `""`. While the owner is open, a new admission may start right after the return; close first if none may start.
- `open(owner)`: `noexcept`; lock; clear `closed`; erase the state if idle. A lock failure leaves the owner closed.
- `admittedOnThisThread(owner)`: `admitted.count(owner) > 0`, no lock. True from `admit` until release -- including while an admitted EventQueue entry waits behind earlier handlers of the same dispatch.

**Invariants.** (1) Admitted and counted implies `inFlight[owner] >= 1` and the owner is in the creating thread's multiset. (2) When `drain(owner)` returns, no counted admission of the owner exists, and none can be created while it stays closed. (3) An owner state exists only while it is closed or has `inFlight > 0`.

### 3.4 Single instances (PAT-3)

`detail::callbackThreadState()` and `CallbackGate::gate()` are declared in the header and defined once in `src/core/iora_core.cpp` when `IORA_CORE_SHARED` / `IORA_CORE_BUILDING` is defined (the normal build). Registration and dispatch code is compiled into plugin `.so` files loaded `RTLD_LOCAL`; a header-inline `thread_local` or static would give each image its own copy, so a host `Scope` would be invisible to a plugin-side registration and a host `close` to a plugin-side `admit`. The header-only fallback (no `iora_core`) defines both inline. The gate is immortal (never destroyed) because a release may run during static destruction. `iora_test_plugin_isolation` checks both across the plugin boundary.

### 3.5 Users

- **`EventQueue`** (`docs/core/event_queue.md` section 3.7): opted-in instances tag entries; dispatch admits each entry under `_mutex`, skips a closed owner's entries, and releases each admission right after its handler.
- **`HttpServer` / `WebhookServer`** (`docs/network/http_server.md` section 5.4): opted-in instances tag routes and the default handler; `classifyRequest` admits before copying; a closed owner yields `OWNER_CLOSED` -> 503; the admission is released right after the dispatch switch.
- **`IoraService`** (`docs/iora_service.md` section 4.6): the plugin lifecycle and contract.

---

## 4. Usage Guide

### 4.1 Owner-tagged registration and removal on an EventQueue

```cpp
#include "iora/core/callback_ownership.hpp"
#include "iora/core/event_queue.hpp"

iora::core::EventQueue queue(2);
queue.enableCallbackOwnerTracking();
{
  iora::core::CallbackOwner::Scope scope("billing");
  queue.onEventName("invoice.created", [](const iora::parsers::Json &) { /* ... */ });
}
// ... later, retire everything "billing" registered:
iora::core::CallbackGate::close("billing");   // new dispatches skip it
iora::core::CallbackGate::drain("billing");   // wait for running handlers (no lock held)
queue.removeHandlersOwnedBy("billing");       // destroyed off the queue lock
iora::core::CallbackGate::open("billing");
```

### 4.2 A route that answers 503 while its owner is closed

```cpp
#include "iora/core/callback_ownership.hpp"
#include "iora/network/http_server.hpp"

iora::network::HttpServer server("127.0.0.1", 8080);
server.enableCallbackOwnerTracking();
{
  iora::core::CallbackOwner::Scope scope("reports");
  server.onGet("/reports", [](const iora::network::HttpServer::Request &,
                              iora::network::HttpServer::Response &res)
               { res.set_content("ok", "text/plain"); });
}
server.start();
iora::core::CallbackGate::close("reports");   // GET /reports -> 503 Service Unavailable
iora::core::CallbackGate::open("reports");    // GET /reports -> 200 again
```

### 4.3 Host code that must stay unowned inside a plugin hook

```cpp
void registerHostMetricsRoute(iora::IoraService &svc)
{
  // May run inside a plugin's onLoad; the route must not belong to that plugin.
  iora::core::CallbackOwner::Scope unowned("");
  svc.webhookServer()->onGet("/metrics", [](const auto &, auto &res) { res.set_content("", "text/plain"); });
}
```

### 4.4 Refusing a self-unload

```cpp
// Inside code that may run in a callback of module `name`:
if (iora::core::CallbackGate::admittedOnThisThread(name))
{
  // draining `name` from this thread would wait for this thread: refuse
}
```

`IoraService::unloadSingleModule` / `reloadModule` throw and `unloadAllModules` skips the module in this case.

### 4.5 Anti-patterns

- **Do NOT call `drain(owner)` while holding a lock an admitted callback may need**, or from a thread that holds an admission of `owner` -- it waits forever.
- **Do NOT release an `Admission` on another thread** (move it into a lambda run elsewhere): the creating thread's multiset keeps a stale entry and its later self-unload checks give false positives.
- **Do NOT wait, inside an owned callback, for another owned callback of an owner that may be closed** (for example push an event and wait for its handler): while closed, that handler is skipped, so the wait never ends and the drain never ends.
- **Do NOT expect an instance that was never opted in to gate or remove anything**: its entries are unowned.
- **Do NOT register from a thread with no scope and expect removal**: the entry is unowned and is never removed by owner.

---

## 5. Call Flow / Sequence Reference

### 5.1 Success -- owned EventQueue handler dispatched while open

| Step | Action | Lock |
|---|---|---|
| 1 | Worker pops the event | `EventQueue::_mutex` (pop) |
| 2 | For the owned entry: `admit(owner)` -> multiset insert; `++inFlight` | `_mutex` -> gate mutex |
| 3 | Copy the handler into `pair<Admission, Handler>` | `_mutex` |
| 4 | Release `_mutex`; invoke the handler | none |
| 5 | `entry.second = nullptr` (handler copy destroyed) | none |
| 6 | `entry.first = Admission{}` -> multiset erase one; `leave`: `--inFlight`, at 0 `notify_all`, erase idle state | gate mutex |

### 5.2 Unload of a closed owner with one handler in flight

| Step | Action | Lock |
|---|---|---|
| 1 | Unloader: `close(owner)` in the claim | `_loadModulesMutex` -> gate mutex |
| 2 | New dispatches: `admit` returns not admitted -> entry skipped / 503 | registry mutex -> gate mutex |
| 3 | Unloader releases `_loadModulesMutex`; `drain(owner)` waits on `drained` | gate mutex (CV wait) |
| 4 | The in-flight handler returns; its release reaches `inFlight == 0` and notifies under the lock | gate mutex |
| 5 | `drain` returns; unloader re-locks; `onUnload`; `removeHandlersOwnedBy(owner)` on both registries; erase; `dlclose` | `_loadModulesMutex` (+ registry mutexes) |
| 6 | `open(owner)` in `openGate` | `_loadModulesMutex` -> gate mutex |

### 5.3 Failure -- `admit` throws during dispatch

`admit` restores the multiset and rethrows (`bad_alloc` / `system_error`). `EventQueue` counts the entry as failed, skips it, and logs one error line after `_mutex` is released; the other handlers still run. In `HttpServer`, the throw propagates out of `classifyRequest` to `processHttpRequest`'s existing catch, which sends its error response.

---

## 6. Thread Safety Model

| Operation | Synchronization | Notes |
|---|---|---|
| `CallbackOwner::current` / `Scope` | thread-local, none | `noexcept`. |
| `CallbackGate::admit("")` | none | Admitted, not counted. |
| `CallbackGate::admit(owner)` | gate mutex | Called under a registry mutex (registry -> gate). Strong guarantee. |
| `Admission` release (destructor / move assignment) | gate mutex (inside `leave`) | Same thread as `admit`. `notify_all` under the lock at zero. |
| `close` | gate mutex | IoraService calls it under `_loadModulesMutex` (L -> gate). |
| `drain` | gate mutex (CV wait) | Caller holds no other lock. Fresh `find` each predicate evaluation. |
| `open` | gate mutex | `noexcept`; a lock failure is swallowed (owner stays closed). |
| `admittedOnThisThread` | thread-local, none | `noexcept`. |

**Lock ordering.** The gate mutex is a **leaf**: no other lock is taken while it is held, no callback runs under it, and nothing is logged under it. Edges into it: `EventQueue::_mutex -> gate`, `HttpServer::_mutex -> gate`, `_loadModulesMutex -> gate`. `drain` runs with no lock held.

---

## 7. Configuration Reference

There is no runtime configuration. The only switch is per registry instance:

| Parameter | Where | Default | Effect |
|---|---|---|---|
| Owner tracking | `EventQueue::enableCallbackOwnerTracking()`, `HttpServer::enableCallbackOwnerTracking()` | off | One-way. Later registrations store `CallbackOwner::current()`. `IoraService` turns it on for its own event queue (constructor) and webhook server (`applyConfig`, before the server is published). |

---

## 8. API Reference

```cpp
namespace iora { namespace core {

namespace detail {
struct CallbackThreadState { std::string owner; std::multiset<std::string> admitted; };
CallbackThreadState &callbackThreadState();
}

class CallbackOwner
{
public:
  static const std::string &current() noexcept;

  class Scope
  {
  public:
    explicit Scope(std::string owner) noexcept;
    ~Scope() noexcept;
    Scope(const Scope &) = delete;
    Scope &operator=(const Scope &) = delete;
  };
};

class CallbackGate
{
public:
  class Admission
  {
  public:
    Admission() noexcept = default;
    Admission(Admission &&other) noexcept;
    Admission &operator=(Admission &&other) noexcept;
    Admission(const Admission &) = delete;
    Admission &operator=(const Admission &) = delete;
    ~Admission();
    explicit operator bool() const noexcept;
  };

  [[nodiscard]] static Admission admit(const std::string &owner);
  static void close(const std::string &owner);
  static void drain(const std::string &owner);
  static void open(const std::string &owner) noexcept;
  static bool admittedOnThisThread(const std::string &owner) noexcept;
};

}} // namespace iora::core
```

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Owner set automatically by the host's `Scope` around each hook (`CB-DP-1`) | No plugin change; existing plugins and the documented `onLoad` pattern are covered, including direct `webhookServer()->onGet` calls. Tokens or an explicit owner parameter would need every plugin to change and would leak silently when forgotten. |
| Admit before copy, release after the copy is destroyed (`CB-DP-2`) | No copy of a closed owner's callback is ever made, and the code of a callback is never destroyed after its owner's drain returned. |
| Closed until the load commits (`CB-DP-3`) | A failed load needs no drain: none of its callbacks was ever admitted. |
| Per-entry release in `EventQueue` | A drain waits only for the handlers that run up to the owner's; a handler after it is not affected. |
| `leave` notifies at every zero, not only for a closed owner | `drain` is correct for an open owner too, and an `open` during a waiting drain cannot strand it. |
| Gate is a separate core primitive, not the `callExportedApi` gate | `EventQueue` and `HttpServer` cannot include `iora.hpp` (layer rule). Unifying the two gates is deferred. |
| One thread-local record and one immortal gate, defined in `iora_core.cpp` (`CB-DP-7`) | A per-image copy would silently disable the gate across the `RTLD_LOCAL` plugin boundary. |
| Opt-in per registry instance (HD-3) | Only the host's two instances are gated; a server or queue a plugin owns keeps today's behavior and cannot hang an unload. |
| Closed route answers 503 (HD-1) | The route exists but is temporarily unavailable; a fall-through would expose another route or 404 during a reload. |
| Unbounded drain (`CB-DP-11`) | Same as the `callExportedApi` drain: a timeout would abort a legitimately long callback and then unload its code under it. |

---

## 10. Known Limitations

- **The drain is unbounded.** A callback that never returns blocks its module's unload and `shutdown()` forever. Waiting without a timeout for another owned callback (for example an event reply) can never end while that owner is closed (section 4.5).
- **Self-unload is refused, not performed.** A thread that holds an admission of M (inside M's callback, or in an EventQueue dispatch where M's handler has not run yet) cannot unload M. Handing that unload to another thread and waiting for it hangs forever.
- **Cross-thread mutual unload is unsupported.** Thread A inside a callback of M unloads N while thread B inside a callback of N unloads M: each drain waits for the other.
- **Attribution follows the hook running on the thread.** A callback registered by another module's code inside your hook (for example through an exported API you call from `onLoad`) is tagged with your module; a callback registered outside any hook (a plugin thread, a callback, a destructor) is unowned and never removed.
- **Only opted-in instances are tracked.** Entries on a registry that never called `enableCallbackOwnerTracking()` are never gated or removed by owner.
- **Owner names share one process-wide namespace.** Owners are plain strings; `IoraService` uses module file names.
- **Two gates exist.** The `callExportedApi` drain gate in `IoraService` and `CallbackGate` have the same shape; `IoraService` drives both at each unload step.
