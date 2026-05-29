// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// TEST-ONLY accessor for iora::ServiceRegistry. This header is NOT installed and
// NOT included by any production translation unit — it lives under tests/ and is
// included only by the ServiceRegistry test suite. It defines the friend struct
// declared (but deliberately left incomplete) in core/service_registry.hpp, so
// the capability to inject registry state the public API forbids exists only
// where this header is included.
//
// Its sole purpose is to exercise the AH-2 survivor-abort defensive guard in
// ServiceRegistry::unregisterModule, which the H-2 set-time empty-moduleId
// rejection makes unreachable through the public API.

#pragma once

#include "iora/core/service_registry.hpp"

#include <cassert>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <typeindex>
#include <typeinfo>

namespace iora
{

/// \brief Test-only accessor that can inject registry state the public API
/// forbids (e.g. an entry with an empty moduleId), so the survivor-abort guard
/// can be tested. Friend of ServiceRegistry (declared in service_registry.hpp).
struct ServiceRegistryTestAccess
{
  /// Insert an Entry with an arbitrary (possibly empty) moduleId, bypassing the
  /// H-2 set-time validation.
  template <typename T>
  static void injectEntry(std::shared_ptr<T> impl, const std::string &moduleId)
  {
    auto &s = ServiceRegistry::storage();
    std::unique_lock<std::shared_mutex> lock(s.mutex);
    auto res = s.map.emplace(
      std::type_index(typeid(T)),
      ServiceRegistry::Entry{std::static_pointer_cast<void>(std::move(impl)), moduleId});
    // emplace is a silent no-op if the key already exists; assert insertion so a
    // test that forgot to clear the registry fails loudly instead of vacuously.
    assert(res.second && "injectEntry: type already registered (clearAll not called?)");
    (void)res;
  }

  /// Clear the entire process-global registry. Used to isolate test cases that
  /// share the singleton: a REQUIRE failure mid-test would otherwise skip a
  /// test's own cleanup and leave a stale entry that breaks the next test.
  static void clearAll()
  {
    auto &s = ServiceRegistry::storage();
    std::unique_lock<std::shared_mutex> lock(s.mutex);
    s.map.clear();
  }
};

} // namespace iora
