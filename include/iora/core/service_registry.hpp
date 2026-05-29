// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <cstdlib>
#include <memory>
#include <mutex>          // std::unique_lock
#include <shared_mutex>   // std::shared_mutex, std::shared_lock
#include <stdexcept>
#include <string>
#include <typeindex>
#include <typeinfo>
#include <unordered_map>

#include "iora/core/logger.hpp"

namespace iora
{

/// \brief Process-wide, type-safe, type-erased registry mapping an interface
/// type to a single concrete implementation provided by a plugin.
///
/// ServiceRegistry is the mechanism by which iora FOUNDATION code calls into an
/// OPTIONAL plugin through an abstract C++ interface. A plugin registers a
/// concrete implementation during Plugin::onLoad via set<T>(impl, moduleId);
/// foundation code retrieves it at request time via get<T>() (nullptr when no
/// plugin registered the interface). It complements — it does NOT replace — the
/// string-keyed callExportedApi dispatch, which remains for user-code callers.
///
/// Storage model (C-4): the set/get/unregister templates and unregisterModule
/// are header-only, but the singleton STORAGE (the type-erased map + its mutex)
/// is a NON-INLINE definition compiled exactly once into libiora_core.so via
/// ServiceRegistry::storage() in src/core/iora_core.cpp. A header-inline static
/// would be emitted per translation unit / per .so under RTLD_LOCAL, so
/// foundation (libiora_core.so) and a plugin (.so) would mutate DIFFERENT maps
/// and get<T>() would never observe a plugin's set<T>(). This is the one
/// deliberate exception to iora's header-only character, identical in spirit to
/// IoraService::getInstancePtr / MetricsRegistry::instance.
///
/// Lifecycle (C-5, RD-7): a plugin's registrations are removed before dlclose by
/// the core-driven unregisterModule(pluginName) call wired into
/// IoraService::unloadSingleModule (symmetric to the unexportApi loop). The
/// shared_ptr<T> returned by get<T>() keeps the OBJECT alive, but its VTABLE
/// lives in the plugin .so code segment and is unmapped by dlclose; using a
/// get<T>() result obtained just before an unload, after dlclose, dereferences
/// an unmapped vtable. unregister-on-unload covers the registry slot only; the
/// get()-racing-unload residual is closed by the drain-before-unload invariant
/// (RD-7): unloadSingleModule MUST NOT run while the HTTP server is started —
/// interface-providing modules unload only AFTER http.stop() has fully drained
/// in-flight handlers. The enforcer of that startup/shutdown ordering is
/// application_wiring (a later phase); this component states and documents the
/// invariant, it does not implement http.start()/http.stop() sequencing.
///
/// ABI invariant (R-12): direct shared_ptr<IFoo> across the .so boundary is safe
/// only when iora core and every interface-providing plugin are built with the
/// same toolchain, default symbol visibility, and RTTI enabled. type_index
/// equality across .so boundaries requires default visibility + RTTI. iora
/// already relies on this for ApiWrapper's type_index dispatch.
class ServiceRegistry
{
public:
  /// \brief Plugin-facing registration. moduleId is MANDATORY (RD-6): it
  /// associates the registration with the owning plugin so unregisterModule can
  /// remove it automatically on unload. Use Plugin::getIdentity() as moduleId
  /// inside onLoad.
  ///
  /// Throws std::invalid_argument if impl is null or moduleId is empty (both
  /// validated lock-free before the write lock). Throws std::runtime_error if a
  /// different impl is already registered for T (duplicate-set is a bug, not a
  /// silent replace — consistent with exportApi).
  template <typename T> static void set(std::shared_ptr<T> impl, const std::string &moduleId)
  {
    // Lock-free validation BEFORE acquiring the write lock (RD-6).
    if (!impl)
    {
      throw std::invalid_argument(std::string("ServiceRegistry::set: null implementation for ") +
                                  typeid(T).name());
    }
    // moduleId is MANDATORY (H-2): rejecting an empty moduleId here is the
    // PRIMARY guard against the AH-2 orphan-entry hole (an entry no module owns
    // and nothing cleans up). The unregisterModule survivor check is the
    // belt-and-suspenders fallback.
    if (moduleId.empty())
    {
      throw std::invalid_argument(std::string("ServiceRegistry::set: empty moduleId for ") +
                                  typeid(T).name());
    }

    const std::type_index key(typeid(T));
    Storage &s = storage();
    std::unique_lock<std::shared_mutex> lock(s.mutex);
    if (s.map.find(key) != s.map.end())
    {
      throw std::runtime_error(std::string("ServiceRegistry::set: type already registered: ") +
                               typeid(T).name());
    }
    s.map.emplace(key, Entry{std::static_pointer_cast<void>(std::move(impl)), moduleId});
  }

  /// \brief Core-internal registration overload (no moduleId). Stores the
  /// reserved sentinel moduleId "\\x00core" (NUL byte + 'core'), which can never
  /// collide with a real Plugin::getIdentity() (a printable .so name). These
  /// entries are process-lifetime: iora core never unloads, so they are never
  /// targeted by unregisterModule and are EXEMPT from the survivor assertion.
  ///
  /// PLUGIN CODE MUST NOT CALL THIS OVERLOAD — plugins must use the (impl,
  /// moduleId) form so their registrations are auto-cleaned on unload.
  template <typename T> static void set(std::shared_ptr<T> impl)
  {
    // Delegate to the plugin-facing form with the non-empty sentinel so the
    // empty-moduleId guard does not fire (the sentinel is 5 bytes, not empty).
    set<T>(std::move(impl), coreSentinel());
  }

  /// \brief Retrieve the implementation registered for T, or nullptr if none.
  /// Hot path: takes only a shared (read) lock and returns a shared_ptr by
  /// value; the caller then uses the impl with NO registry lock held. Returns
  /// nullptr (NOT an exception) when no plugin registered the interface — an
  /// absent optional plugin is a runtime condition for the caller to handle.
  template <typename T> static std::shared_ptr<T> get()
  {
    const std::type_index key(typeid(T));
    Storage &s = storage();
    std::shared_lock<std::shared_mutex> lock(s.mutex);
    auto it = s.map.find(key);
    if (it == s.map.end())
    {
      return nullptr;
    }
    return std::static_pointer_cast<T>(it->second.impl);
  }

  /// \brief Remove the registration for a single interface type T. Returns true
  /// if an entry was removed, false if none was present. Used by a plugin in
  /// onUnload to clear one interface before dlclose; symmetric to unexportApi.
  template <typename T> static bool unregister()
  {
    const std::type_index key(typeid(T));
    Storage &s = storage();
    std::unique_lock<std::shared_mutex> lock(s.mutex);
    return s.map.erase(key) > 0;
  }

  /// \brief Remove ALL registrations owned by moduleId. The bulk-cleanup analog
  /// of the unexportApi loop; called automatically by unloadSingleModule with
  /// the plugin name before dlclose. Idempotent (a module with zero
  /// registrations is a no-op).
  ///
  /// While iterating under the write lock it detects misuse (RD-6 / AH-2): any
  /// SURVIVING non-core entry with an empty moduleId is owned by nothing and
  /// would dangle after dlclose, so it logs and aborts. "\\x00core" entries are
  /// exempt (process-lifetime, non-empty moduleId).
  ///
  /// MUST NOT propagate exceptions (M-3): this runs inside the try block of
  /// IoraService::unloadSingleModule, before dlclose; a throw would be swallowed
  /// by the unload catch and SKIP dlclose, leaking the module. The misuse path
  /// therefore aborts (NDEBUG-independent) rather than throwing.
  static void unregisterModule(const std::string &moduleId) noexcept
  {
    Storage &s = storage();
    std::unique_lock<std::shared_mutex> lock(s.mutex);
    for (auto it = s.map.begin(); it != s.map.end();)
    {
      if (it->second.moduleId == moduleId)
      {
        it = s.map.erase(it);
      }
      else
      {
        // AH-2 survivor detection: an entry with an EMPTY moduleId is orphaned —
        // owned by no module and never cleaned up. Plugin entries have a
        // non-empty moduleId (H-2 rejects empty at set time) and core entries
        // have the non-empty "\x00core" sentinel, so neither reaches this branch;
        // only state injected outside the public API can. Checking .empty() alone
        // is sufficient and surfaces an H-1 regression (an empty sentinel) loudly.
        if (it->second.moduleId.empty())
        {
          IORA_LOG_ERROR("ServiceRegistry::unregisterModule: orphaned registration with empty "
                         "moduleId survives unload of '" +
                         moduleId + "' — registration owned by no module (AH-2 misuse)");
          std::abort();
        }
        ++it;
      }
    }
  }

private:
  /// \brief A single registration: the type-erased implementation plus the id of
  /// the module that owns it (for unregisterModule). PRIVATE NESTED (RD-6).
  struct Entry
  {
    std::shared_ptr<void> impl;
    std::string moduleId;
  };

  /// \brief The backing store. PRIVATE NESTED (RD-6); only ServiceRegistry's own
  /// methods and the out-of-line storage() definition can name it.
  ///
  /// Lock ordering: the only edge INVOLVING this mutex is
  /// IoraService::_loadModulesMutex -> ServiceRegistry::Storage::mutex (the set
  /// path runs under _loadModulesMutex during onLoad; the unregister path runs
  /// under _loadModulesMutex during unloadSingleModule). There is NO reverse
  /// edge: get<T>() takes ONLY this shared lock and never acquires
  /// _loadModulesMutex. For context, the surrounding load/unload code also has
  /// the edge _loadModulesMutex -> IoraService::_apiMutex (the exportApi /
  /// unexportApi loop), but _apiMutex and this registry mutex are NEVER held
  /// simultaneously: unloadSingleModule runs the whole unexportApi loop (each
  /// call takes and releases _apiMutex) and only THEN calls unregisterModule
  /// (which takes this mutex). So there is no _apiMutex <-> registry edge and no
  /// cycle. Otherwise this mutex is a LEAF — never held while acquiring
  /// HttpServer::_mutex or IoraService::_apiMutex, and no user callback is
  /// invoked while it is held (get returns the shared_ptr, then the caller
  /// invokes interface methods lock-free).
  struct Storage
  {
    std::unordered_map<std::type_index, Entry> map;
    std::shared_mutex mutex;
  };

  /// \brief Accessor for the single process-wide Storage. DECLARED here, DEFINED
  /// exactly once in src/core/iora_core.cpp (C-4) so there is one registry per
  /// process, shared by libiora_core.so and every plugin .so.
  static Storage &storage();

  /// \brief Reserved sentinel moduleId for core-internal registrations. Built
  /// with EXPLICIT length 5 (H-1) — a std::string constructed from the bare
  /// const char* "\\x00core" would truncate at the embedded NUL and yield an
  /// empty string, silently disabling the survivor assertion. The bytes are
  /// {NUL,'c','o','r','e'}; .size() == 5.
  static const std::string &coreSentinel()
  {
    static const std::string sentinel("\x00core", 5);
    return sentinel;
  }

  // Test-only access. The H-2 set-time empty-moduleId rejection makes the AH-2
  // survivor-abort path in unregisterModule unreachable through the public API,
  // so exercising that defensive guard requires injecting an empty-moduleId
  // entry directly into storage(). Only the GRANT lives here (a friend
  // declaration of an incomplete type); the struct is DEFINED solely in the
  // test-only header tests/web/service_registry_test_access.hpp, so production
  // TUs that include this header gain no usable capability (they see only an
  // incomplete type they cannot call).
  friend struct ServiceRegistryTestAccess;
};

} // namespace iora
