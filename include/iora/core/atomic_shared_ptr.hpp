// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <memory>
#include <utility>

namespace iora
{
namespace core
{

/// \brief An atomically-published std::shared_ptr slot (C++17).
///
/// Encapsulates the C++17 std::atomic_load/store/exchange FREE-FUNCTION idiom on
/// a shared_ptr member (std::atomic<std::shared_ptr<T>> is C++20 — NOT used).
/// Because the wrapped member is private and there is no raw accessor, a reader
/// or writer that bypasses the atomic idiom becomes a COMPILE error rather than a
/// silent data race (mixing atomic and non-atomic access to the same shared_ptr
/// is UB, and — since the member type would otherwise be unchanged — the compiler
/// cannot catch a stray raw access; this wrapper makes the grep gate mechanical).
///
/// Every reader should snapshot ONCE into a local (load() takes the shared_ptr
/// atomic's internal spinlock table, so a multi-field read must pin one snapshot).
///
/// Defaults: acquire on load, release on store, acq_rel on exchange — the intent-
/// legible orders for safe publication. When the project moves to C++20, only this
/// wrapper changes (to std::atomic<std::shared_ptr<T>>), not its call sites.
template <typename T> class AtomicSharedPtr
{
public:
  AtomicSharedPtr() = default;
  explicit AtomicSharedPtr(std::shared_ptr<T> initial) : _p(std::move(initial)) {}

  AtomicSharedPtr(const AtomicSharedPtr &) = delete;
  AtomicSharedPtr &operator=(const AtomicSharedPtr &) = delete;

  /// \brief Snapshot the current pointer.
  std::shared_ptr<T> load(std::memory_order order = std::memory_order_acquire) const
  {
    return std::atomic_load_explicit(&_p, order);
  }

  /// \brief Publish a new pointer.
  void store(std::shared_ptr<T> value, std::memory_order order = std::memory_order_release)
  {
    std::atomic_store_explicit(&_p, std::move(value), order);
  }

  /// \brief Atomically replace and return the previous pointer.
  std::shared_ptr<T> exchange(std::shared_ptr<T> value,
                              std::memory_order order = std::memory_order_acq_rel)
  {
    return std::atomic_exchange_explicit(&_p, std::move(value), order);
  }

private:
  std::shared_ptr<T> _p;
};

} // namespace core
} // namespace iora
