# Iora Web Middleware Interfaces — Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-22 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/web/middleware_interfaces.hpp` (header-only) |
| **Namespace** | `iora::web` |
| **Dependencies** | `iora/parsers/json.hpp`, `iora/network/http_server.hpp` (`HttpServer::Request` / `HttpServer::Response`); `<optional>`, `<string>`, `<string_view>` |
| **Conformance suites** | `tests/web/conformance/{IAuthGuard,ISessionStore,ICsrfProtector,ILoginUiProvider}Conformance.hpp` |
| **Architecture** | `architecture/iora/service_registry_and_interfaces.json` |
| **Related** | [service_registry.md](../core/service_registry.md) (the DI seam), [application.md](application.md) (the web facade) |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-22 | Initial guide. Documents the four pluggable web-middleware interface contracts (`IAuthGuard`, `ISessionStore`, `ICsrfProtector`, `ILoginUiProvider`) and the `Identity`/`Session` value types, their graceful-degradation contract, the `ServiceRegistry` publication seam, and the in-tree executable conformance suites a downstream implementation is verified against. |

---

## 1. Executive Summary

### Problem

`iora::web::Application` provides a server-rendered HTMX admin surface, but it deliberately ships **no** authentication, session, or CSRF machinery — full auth (login UI, OIDC/LDAP, session stores, CSRF tokens) is a large, deployment-specific concern that does not belong in the foundation library. Yet the foundation must still be able to *call into* an auth layer without depending on any concrete implementation, and without a stringly-typed plugin protocol. Two things are needed: a set of **abstract C++ contracts** the foundation can call through, and a way for the foundation to **degrade gracefully** when a given contract is not supplied.

### Solution

`include/iora/web/middleware_interfaces.hpp` defines four pure-virtual interfaces and two plain value types in `iora::web`:

- **`IAuthGuard`** — authenticate an inbound request → `std::optional<Identity>`.
- **`ISessionStore`** — create / look up / update / destroy server-side sessions.
- **`ICsrfProtector`** — mint and verify CSRF tokens scoped to a session.
- **`ILoginUiProvider`** — render the login page and handle login POSTs (**optional**).
- **`Identity`** / **`Session`** — the value types the interfaces exchange, each carrying an open `iora::parsers::Json` the foundation never interprets.

These are **contracts only**: iora ships no concrete implementation. A downstream middleware (e.g. `iora_web_middleware`) implements them and publishes each through the type-safe [`ServiceRegistry`](../core/service_registry.md); foundation code retrieves them with `ServiceRegistry::get<T>()`, which returns `nullptr` (not an exception) when none is registered, so an absent optional interface is a first-class, handled state.

### Technical Impact

The foundation↔auth boundary is a set of C++ interfaces, not string keys — resolution is type-checked, and an unregistered interface is a `nullptr` the caller handles rather than a runtime lookup miss. iora also ships **executable conformance suites** for each interface, so a downstream implementation proves it satisfies the contract with a one-line test instantiation rather than re-deriving the contract from prose.

---

## 2. System Architecture

### Position in the stack

```
   +------------------------------------------------------------------+
   |  Foundation handler code (a consumer wiring; NOT Application itself) |
   |    calls ServiceRegistry::get<IAuthGuard>()  -> shared_ptr or nullptr
   +---------------------------+--------------------------------------+
                               | resolves through
                               v
   +------------------------------------------------------------------+
   |  iora::core::ServiceRegistry  (type-safe, process-wide DI seam)   |
   +---------------------------+--------------------------------------+
                               ^ set<IAuthGuard>(impl, moduleId) in Plugin::onLoad
                               |
   +---------------------------+--------------------------------------+
   |  Downstream middleware plugin (e.g. iora_web_middleware)          |
   |    implements IAuthGuard / ISessionStore / ICsrfProtector / ...   |
   +------------------------------------------------------------------+
```

`middleware_interfaces.hpp` is a **tier-0 contract header**: it defines the boundary and depends only on the request/response types and `Json`. The interfaces flow one way (foundation calls down through the registry); the value types (`Identity`, `Session`) flow back up.

### The value types

| Type | Fields | Meaning |
|---|---|---|
| `Identity` | `std::string subject`, `iora::parsers::Json claims` | The authenticated principal. `subject` is the stable user id (username or OIDC `sub`); `claims` is an open object (roles, display name, provider attributes) iora **never interprets** — consumers read by key, never by position (Json objects are unordered). |
| `Session` | `std::string id`, `iora::parsers::Json data` | A server-side session record. `id` is the opaque identifier (carried in the session cookie by the middleware); `data` is session state iora **never inspects**. |

### Threading model

The header defines contracts, not behavior, so it introduces no threads or locks of its own. However, a registered implementation is a **process-wide singleton reachable from every `HttpServer` worker thread concurrently** (`ServiceRegistry::get<T>()` returns a shared `shared_ptr`). The contract therefore requires each implementation's methods to be **safe for concurrent invocation** — see §6.

---

## 3. Component Deep Dive

### `IAuthGuard`

```cpp
class IAuthGuard
{
public:
  virtual ~IAuthGuard() = default;
  virtual std::optional<Identity> authenticate(const network::HttpServer::Request& req) = 0;
};
```

Authenticate an inbound request. Returning `std::nullopt` is **not an error** — it means "unauthenticated", and the foundation caller decides what to do (redirect to login, issue a challenge, or 401). An implementation reads whatever it needs from `req` (a session cookie, a bearer token, a Basic header) and either resolves an `Identity` or returns `nullopt`.

### `ISessionStore`

```cpp
class ISessionStore
{
public:
  virtual ~ISessionStore() = default;
  virtual std::optional<Session> get(const std::string& sessionId) = 0;   // nullopt if unknown/expired
  virtual std::string create(const iora::parsers::Json& initial) = 0;     // -> new opaque id
  virtual void update(const std::string& sessionId, const iora::parsers::Json& data) = 0;
  virtual void destroy(const std::string& sessionId) = 0;                  // idempotent
};
```

Create / look up / update / destroy server-side sessions keyed by an opaque id. `get` returns `nullopt` for an unknown or expired id; `create` persists the initial `Json` and returns a fresh opaque id; `update` replaces the stored data; `destroy` removes the session and is **idempotent** (destroying an unknown id is a no-op, not an error).

### `ICsrfProtector`

```cpp
class ICsrfProtector
{
public:
  virtual ~ICsrfProtector() = default;
  virtual std::string mint(const std::string& sessionId) = 0;                    // fresh token bound to the session
  virtual bool verify(const std::string& sessionId, const std::string& token) = 0;
};
```

Mint and verify CSRF tokens scoped to a session. `mint` returns a fresh token bound to `sessionId`; `verify` returns `true` iff the token is valid for that session. The binding and token format are the implementation's choice (signed double-submit, per-session nonce set, etc.); the contract fixes only the mint/verify shape.

### `ILoginUiProvider` (optional)

```cpp
class ILoginUiProvider
{
public:
  virtual ~ILoginUiProvider() = default;
  virtual std::string renderLoginPage(const network::HttpServer::Request& req,
                                      const std::string& errorMessage) = 0;
  virtual std::optional<std::string> handleLoginPost(const network::HttpServer::Request& req,
                                                     network::HttpServer::Response& res) = 0;
};
```

Render the login page and handle login POSTs. `renderLoginPage` returns the login-form HTML, optionally surfacing `errorMessage` (empty string = no error). `handleLoginPost` validates credentials; on success it establishes a session and sets the session cookie on `res`, returning the post-login redirect target — a value = redirect URL, `nullopt` = stay and re-render with an error.

**This interface is OPTIONAL.** The foundation MUST treat `ServiceRegistry::get<ILoginUiProvider>() == nullptr` as "no login UI configured" and degrade gracefully — for example, falling back to [`network::requireBasicAuth`](../network/http_basic_auth.md). A middleware that only needs API-token auth simply never registers an `ILoginUiProvider`, and the foundation adapts without a code change.

---

## 4. Usage Guide

### Implementing and publishing a contract (downstream plugin)

```cpp
#include <iora/web/middleware_interfaces.hpp>
#include <iora/core/service_registry.hpp>

class MyAuthGuard : public iora::web::IAuthGuard
{
public:
  std::optional<iora::web::Identity>
  authenticate(const iora::network::HttpServer::Request& req) override
  {
    const std::string sid = sessionCookie(req);
    if (sid.empty())
    {
      return std::nullopt;                 // unauthenticated -- NOT an error
    }
    iora::web::Identity id;
    id.subject = lookupSubject(sid);
    id.claims  = lookupClaims(sid);        // open Json the foundation never reads
    return id;
  }
};

// In Plugin::onLoad, publish through the type-safe seam; auto-unregistered on unload.
iora::core::ServiceRegistry::set<iora::web::IAuthGuard>(
  std::make_shared<MyAuthGuard>(), getIdentity());
```

### Consuming a contract (foundation / handler)

```cpp
auto guard = iora::core::ServiceRegistry::get<iora::web::IAuthGuard>();
if (!guard)
{
  // No auth middleware configured -- fall back to Basic auth, or allow, per policy.
  return requireBasicAuthOr401(req, res);
}
std::optional<iora::web::Identity> id = guard->authenticate(req);
if (!id)
{
  auto ui = iora::core::ServiceRegistry::get<iora::web::ILoginUiProvider>();
  if (ui)
  {
    res.set_content(ui->renderLoginPage(req, ""), "text/html; charset=utf-8");
    res.status = 401;
  }
  else
  {
    challengeWithBasicAuth(res);           // graceful degradation
  }
  return;
}
// ... proceed as id->subject ...
```

### Verifying an implementation against the contract

Each interface ships an **executable conformance suite** in `tests/web/conformance/`. The suite lives in iora's tree but is not compiled or run in iora's CI (iora ships no implementation to instantiate it against); a downstream plugin includes it and supplies a `Traits` type binding the concrete implementation:

```cpp
#include "web/conformance/IAuthGuardConformance.hpp"

struct MyAuthGuardTraits
{
  static std::shared_ptr<iora::web::IAuthGuard> makeGuard();
  static iora::network::HttpServer::Request makeAnonymousRequest();
  static iora::network::HttpServer::Request makeAuthenticatedRequest();
  static std::string expectedSubject();
};

TEST_CASE("MyAuthGuard conformance")
{
  iora::web::conformance::runIAuthGuardConformance<MyAuthGuardTraits>();
}
```

### Anti-patterns

- **Do NOT treat `authenticate() == nullopt` as an error.** It is the normal "unauthenticated" signal; decide policy (challenge/redirect/401) at the call site.
- **Do NOT interpret `Identity::claims` or `Session::data` positionally.** They are unordered `Json` objects — read by key.
- **Do NOT assume an `ILoginUiProvider` is present.** Always null-check `get<ILoginUiProvider>()` and degrade.
- **Do NOT throw from `ISessionStore::destroy` on an unknown id.** The contract is idempotent.
- **Do NOT publish an implementation outside `Plugin::onLoad` / without a module id** — registering with `getIdentity()` is what lets the registry auto-unregister it on unload.

---

## 5. Call Flow / Sequence Reference

### Authenticated request lifecycle

| Step | Actor | Action |
|---|---|---|
| 1 | worker | handler calls `ServiceRegistry::get<IAuthGuard>()` |
| 2 | registry | returns the registered `shared_ptr<IAuthGuard>`, or `nullptr` |
| 3a | worker | `nullptr` → degrade (Basic auth, or policy default) |
| 3b | worker | non-null → `guard->authenticate(req)` |
| 4 | impl | reads the session cookie / token; resolves an `Identity` or `nullopt` |
| 5 | worker | `nullopt` → `get<ILoginUiProvider>()`; present → render login (401); absent → Basic-auth challenge |
| 6 | worker | `Identity` present → proceed as `id->subject`, reading `id->claims` by key |

### Login POST lifecycle

| Step | Actor | Action |
|---|---|---|
| 1 | worker | POST to the login route → `ui->handleLoginPost(req, res)` |
| 2 | impl | validates credentials; on success `sessionStore->create(initial)` → id; sets the session cookie on `res` |
| 3 | impl | returns the redirect URL (success) or `nullopt` (re-render with error) |
| 4 | worker | value → redirect; `nullopt` → `ui->renderLoginPage(req, "invalid credentials")` |

---

## 6. Thread Safety Model

The header adds no synchronization; it specifies the contract each implementation must meet. A registered implementation is a process-wide singleton called concurrently from many `HttpServer` worker threads, so:

| Interface | Concurrency requirement on the implementation |
|---|---|
| `IAuthGuard::authenticate` | Reentrant; safe for concurrent calls on distinct requests. Typically read-mostly against a session/token store. |
| `ISessionStore::get/create/update/destroy` | Safe for concurrent calls across different session ids; `create` must mint unique ids under contention; `destroy` idempotent. |
| `ICsrfProtector::mint/verify` | Safe for concurrent mint/verify; the token store must tolerate interleaving. |
| `ILoginUiProvider::renderLoginPage/handleLoginPost` | Reentrant; `handleLoginPost` mutates only the passed `res` and the (thread-safe) session store. |

`ServiceRegistry::get<T>()` itself is synchronized and returns a `shared_ptr` copy, so resolution never races publication/unload (the registry's drain-before-unload invariant — see [service_registry.md](../core/service_registry.md)).

---

## 7. Configuration Reference

None. This header defines interface contracts and value types with no configurable parameters and no build options of its own. It compiles wherever `iora/network/http_server.hpp` and `iora/parsers/json.hpp` are available.

---

## 8. API Reference

```cpp
namespace iora::web
{
struct Identity
{
  std::string subject;
  iora::parsers::Json claims;
};

struct Session
{
  std::string id;
  iora::parsers::Json data;
};

class IAuthGuard
{
public:
  virtual ~IAuthGuard() = default;
  virtual std::optional<Identity> authenticate(const network::HttpServer::Request& req) = 0;
};

class ISessionStore
{
public:
  virtual ~ISessionStore() = default;
  virtual std::optional<Session> get(const std::string& sessionId) = 0;
  virtual std::string create(const iora::parsers::Json& initial) = 0;
  virtual void update(const std::string& sessionId, const iora::parsers::Json& data) = 0;
  virtual void destroy(const std::string& sessionId) = 0;
};

class ICsrfProtector
{
public:
  virtual ~ICsrfProtector() = default;
  virtual std::string mint(const std::string& sessionId) = 0;
  virtual bool verify(const std::string& sessionId, const std::string& token) = 0;
};

class ILoginUiProvider
{
public:
  virtual ~ILoginUiProvider() = default;
  virtual std::string renderLoginPage(const network::HttpServer::Request& req,
                                      const std::string& errorMessage) = 0;
  virtual std::optional<std::string> handleLoginPost(const network::HttpServer::Request& req,
                                                     network::HttpServer::Response& res) = 0;
};
}
```

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Foundation↔auth boundary is abstract C++ interfaces resolved through `ServiceRegistry`, not string keys (LD-8) | Type-checked resolution; an unregistered interface is a `nullptr` the caller handles, not a stringly-typed lookup miss. |
| `authenticate` returns `std::optional<Identity>`, and `nullopt` is not an error | Unauthenticated is a normal, expected state; conflating it with an exception would force try/catch on the hot path and lose the "challenge vs 401 vs redirect" decision at the call site. |
| `ILoginUiProvider` is optional; the foundation degrades on `get<ILoginUiProvider>() == nullptr` | A token-only deployment needs no login UI; making it optional lets the same foundation serve both interactive and API-only middlewares with no code change. |
| `Identity::claims` / `Session::data` are open `Json` the foundation never interprets | The foundation cannot anticipate every provider's attribute set; an open object keeps the contract stable while letting middlewares carry arbitrary state. |
| The header includes the full `http_server.hpp` rather than forward-declaring `Request`/`Response` (L-1/L-2) | `HttpServer::Request`/`Response` are nested types, and a nested type cannot be forward-declared from outside its enclosing class in C++ — there is no syntax to name `HttpServer::Request` without the full `HttpServer` definition. The cost (pulling in the HTTP server header) is unavoidable, not a stylistic choice. |
| Each interface ships an executable conformance suite in-tree, not run by iora's CI | The contract's precise semantics (nullopt-for-anonymous, idempotent destroy, unique ids) are pinned as runnable assertions a downstream impl instantiates via a `Traits` binding — the executable form of the contract, verified where the implementation actually lives. |

---

## 10. Known Limitations

- **No concrete implementation ships with iora.** These are contracts only; a working auth layer (sessions/CSRF/login/OIDC/LDAP) is a downstream middleware such as `iora_web_middleware`.
- **The conformance suites are not exercised in iora's CI.** iora has no implementation to instantiate them against, so they compile and run only in the consuming plugin's CI. A change to an interface's semantics must be mirrored into its conformance suite by hand.
- **`Application` does not auto-wire these interfaces.** The current [`Application`](application.md) facade provides no built-in resolution of `IAuthGuard`/`ISessionStore`/`ICsrfProtector`/`ILoginUiProvider`; a consumer wires authentication into its handlers explicitly (resolving via `ServiceRegistry` and applying policy).
- **The contract fixes shapes, not semantics of tokens or sessions.** Token format, session expiry, cookie attributes, and CSRF strategy are entirely the implementation's responsibility; the interfaces cannot enforce, for example, that a CSRF token is actually bound to its session.
- **`Identity`/`Session` carry `Json` by value.** Large claim/session payloads are copied when an `Identity`/`Session` is returned; implementations that carry heavy state should keep the `Json` lean and store the bulk in their own backing store.
