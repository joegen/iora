// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <thread>

namespace iora
{
namespace core
{

/// \brief A race-free, published "which thread am I?" stamp.
///
/// Wraps a std::atomic<std::thread::id> stamped at a worker thread's loop entry
/// and cleared at its exit, so ANY thread can ask "am I the stamped thread?"
/// concurrently with the worker starting/stopping without a data race (reading a
/// raw std::thread would be one). This is the single home of an idiom that was
/// hand-rolled in three places (detail::EngineBase::_ioThreadId, TimerService's
/// run-loop id, DnsTransport's cleanup-thread id).
///
/// std::thread::id is trivially copyable, so std::atomic<std::thread::id> is
/// lock-free on Linux (an id wraps pthread_t). Relaxed ordering suffices for
/// every operation: the value is only ever equality-compared against a thread's
/// own id and publishes no companion data, so it carries no happens-before of its
/// own — the comparison is self-consistent via the stamping thread's program
/// order, and any cross-thread ordering the caller needs comes from a separate
/// mutex/atomic it already holds.
///
/// Recycled-id window: after a DETACHED stamped thread terminates without clearing
/// (or before clearIfCurrent() runs), the OS may reuse its id for a new thread; a
/// matches()/isCurrentThread() by that new thread could then falsely match a stale
/// stamp. This is benign for every current use: a false positive only makes a
/// caller take an early-return "I am the worker" branch, and the paths that use it
/// (teardown-latch exemption, I/O-thread re-entry refusal) stay correct if a
/// genuinely-independent caller is treated as the worker — the real worker/driver
/// still completes the teardown. A join-on-stop thread (engine/timer) has no such
/// window (its id is cleared before the thread is joinable-reused). If a use ever
/// needs to be hardened, gate on a monotonic epoch rather than the raw id.
class AtomicThreadId
{
public:
  /// \brief Stamp the CURRENT thread. Call first-thing in the worker's loop.
  void stamp() noexcept { _id.store(std::this_thread::get_id(), std::memory_order_relaxed); }

  /// \brief Clear the stamp (back to "no thread"). Call at loop exit, so
  /// isCurrentThread() returns false post-exit and never yields a recycled-id
  /// false positive.
  void clear() noexcept { _id.store(std::thread::id{}, std::memory_order_relaxed); }

  /// \brief Clear ONLY if the current thread is still the stamped one.
  ///
  /// Resurrect-safe: when a stale detached worker and a freshly-minted successor
  /// briefly overlap, the stale worker's exit must not wipe the successor's fresh
  /// stamp. The CAS clears iff the slot still holds THIS thread's id.
  void clearIfCurrent() noexcept
  {
    std::thread::id expected = std::this_thread::get_id();
    _id.compare_exchange_strong(expected, std::thread::id{}, std::memory_order_relaxed);
  }

  /// \brief Is the calling thread the stamped one?
  bool isCurrentThread() const noexcept
  {
    return _id.load(std::memory_order_relaxed) == std::this_thread::get_id();
  }

  /// \brief Is \p t the stamped thread? (For deciding about a thread other than
  /// the caller, or when the caller already holds its own id in a local.)
  bool matches(std::thread::id t) const noexcept
  {
    return _id.load(std::memory_order_relaxed) == t;
  }

private:
  std::atomic<std::thread::id> _id{};
};

} // namespace core
} // namespace iora
