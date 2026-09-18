// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.
//
// ExternalClockIdleMap<Key, Value, TimePoint> — a caller-clocked (no internal
// clock), idle(last-activity)-timeout, copy-then-invoke-eviction map with NO
// background thread. The caller supplies `now` on every mutating/lookup op and
// drives expiry via sweepExpired(now) / drainAll(); the map never reads a clock
// and never spawns a thread. This is the tier-0 foundation primitive for
// deterministic, externally-clocked expiry (first consumer: iora_voipmon's C7
// call-table, driven by packet time).
//
// SINGLE-CONSUMER CONTRACT (v1): this map is caller-serialized. It takes NO
// internal lock; the caller guarantees serialized access. Copy-then-invoke +
// per-victim exception isolation are still honored so the eviction callback may
// safely re-enter the map and may throw without corrupting a drain. A
// thread-safe (internally synchronized) variant is a deliberate follow-on, out
// of v1 scope.
//
// SIBLING, NOT A REPLACEMENT: iora's TtlMap (util/ttl_map.hpp) and ExpiringCache
// (util/expiring_cache.hpp) hardcode steady_clock and run background sweeper
// threads, so they cannot be driven by an external clock or replayed
// deterministically. This map is intentionally a third, separate primitive and
// must NOT be folded into any TtlMap/ExpiringCache consolidation.

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace iora
{
namespace util
{

/// Reason an entry left the map through the eviction callback. Explicit removal
/// via erase() and overwrite via put() never fire the callback, so a reason is
/// always one of these three expiry paths.
enum class EvictReason
{
  IDLE_TIMEOUT, ///< sweepExpired(now): (now - lastActivity) > idleTimeout.
  LRU_BOUND,    ///< maxEntries exceeded: min-(lastActivity, insertSeq) victim.
  DRAIN         ///< drainAll(): end-of-capture flush of every entry.
};

namespace detail
{

/// Duration-signedness trait. A chrono Duration reports signedness through its
/// ::rep; a plain integral/arithmetic Duration (from a non-chrono TimePoint)
/// reports it directly. A signed Duration is what makes a backward `now` yield a
/// negative delta instead of an unsigned wrap.
template <typename D, typename = void>
struct DurationIsSigned : std::is_signed<D>
{
};

template <typename D>
struct DurationIsSigned<D, std::void_t<typename D::rep>> : std::is_signed<typename D::rep>
{
};

/// Detects TimePoint LessThanComparable (operator< yielding a bool-convertible).
template <typename T, typename = void>
struct HasLess : std::false_type
{
};

template <typename T>
struct HasLess<T, std::void_t<decltype(std::declval<const T &>() < std::declval<const T &>())>>
    : std::true_type
{
};

/// Detects (TimePoint - TimePoint).
template <typename T, typename = void>
struct HasSubtract : std::false_type
{
};

template <typename T>
struct HasSubtract<T, std::void_t<decltype(std::declval<const T &>() - std::declval<const T &>())>>
    : std::true_type
{
};

} // namespace detail

/// A caller-clocked, idle-timeout, copy-then-invoke-eviction map.
///
/// @tparam Key       Hashable / equality-comparable (Hash + Eq only; NOT
///                   required to be LessThanComparable).
/// @tparam Value     Move-constructible.
/// @tparam TimePoint Caller-supplied time type: LessThanComparable and
///                   subtractable, with (TimePoint - TimePoint) yielding a
///                   SIGNED Duration. Never read from a clock by the map.
template <typename Key, typename Value, typename TimePoint>
class ExternalClockIdleMap
{
public:
  /// Deduced from the TimePoint difference; must be signed (see designPrinciples
  /// BACKWARD/REORDERED now). For a chrono TimePoint this is a chrono duration;
  /// for a plain integral TimePoint it is that integral type.
  using Duration = decltype(std::declval<TimePoint>() - std::declval<TimePoint>());

  static_assert(detail::HasLess<TimePoint>::value, "TimePoint must be LessThanComparable");
  static_assert(detail::HasSubtract<TimePoint>::value,
                "TimePoint must support (TimePoint - TimePoint) -> Duration");
  static_assert(detail::DurationIsSigned<Duration>::value,
                "Duration (TimePoint - TimePoint) must be SIGNED so a backward 'now' yields a "
                "negative delta, not an unsigned wrap");
  static_assert(std::is_move_constructible<Value>::value, "Value must be move-constructible");

  /// Fired ONLY on the three expiry paths (never on erase()/overwrite). The
  /// value is moved out of the map before invocation; the const Key& references
  /// a copy owned by the eviction machinery, not an erased node. The callback
  /// may re-enter the map and may throw (it is isolated per victim), but SHOULD
  /// itself be noexcept.
  using EvictionCallback = std::function<void(const Key &, Value &&, EvictReason)>;

  /// Constructs a Value on a getOrCreate() miss.
  using FactoryFn = std::function<Value()>;

  /// @param idleTimeout Entries expire when (now - lastActivity) > idleTimeout
  ///                    (STRICTLY greater; exactly-at-boundary is not expired).
  /// @param onEvict     Eviction callback; may be empty (an empty callback still
  ///                    evicts + counts).
  /// @param maxEntries  Optional memory cap. std::nullopt = unbounded; 0 is
  ///                    rejected (a zero-capacity map is a usage error).
  /// @throws std::invalid_argument if maxEntries == 0.
  ExternalClockIdleMap(Duration idleTimeout, EvictionCallback onEvict,
                       std::optional<std::size_t> maxEntries = std::nullopt)
      : _idleTimeout(idleTimeout), _onEvict(std::move(onEvict)), _maxEntries(maxEntries)
  {
    if (_maxEntries.has_value() && *_maxEntries == 0)
    {
      throw std::invalid_argument(
          "ExternalClockIdleMap: maxEntries must be > 0 (use std::nullopt for unbounded)");
    }
  }

  // Copy and move deleted: the eviction-callback identity and the single-consumer
  // contract make copying/moving a live map meaningless and error-prone (mirrors
  // TtlMap). A move variant, if ever wanted, is a deliberate follow-on.
  ExternalClockIdleMap(const ExternalClockIdleMap &) = delete;
  ExternalClockIdleMap &operator=(const ExternalClockIdleMap &) = delete;
  ExternalClockIdleMap(ExternalClockIdleMap &&) = delete;
  ExternalClockIdleMap &operator=(ExternalClockIdleMap &&) = delete;

  /// Insert or overwrite `key`; sets lastActivity = now. Overwrite is SILENT (no
  /// onEvict) and preserves the entry's insertSeq. If an insert exceeds
  /// maxEntries, the min-(lastActivity, insertSeq) entry is evicted with
  /// LRU_BOUND AFTER the insert (self-eviction is tolerated here — put() returns
  /// void, so a just-inserted entry that is genuinely the minimum under a
  /// backward `now` may itself be the victim; deterministic and acceptable).
  void put(const Key &key, Value value, TimePoint now)
  {
    auto it = _map.find(key);
    if (it != _map.end())
    {
      it->second.value = std::move(value);
      it->second.lastActivity = now;
      return;
    }
    _map.emplace(key, Node{std::move(value), now, _seqCounter++});
    enforceBound(_map.end());
  }

  /// Lookup; on hit REFRESH lastActivity = now (idle = last-activity) and return
  /// a pointer to the stored value; nullptr on miss. The returned pointer stays
  /// valid until THAT key is erased/evicted/the map is destroyed; it is NOT
  /// invalidated by operations on other keys nor by rehash (std::unordered_map
  /// references are stable across insert/rehash).
  Value *get(const Key &key, TimePoint now)
  {
    auto it = _map.find(key);
    if (it == _map.end())
    {
      return nullptr;
    }
    it->second.lastActivity = now;
    return &it->second.value;
  }

  /// Return the existing value (refreshing lastActivity = now) OR, on miss,
  /// insert makeValue()-constructed value with lastActivity = now and return a
  /// reference to it. This is the create-on-miss seam a correlator needs.
  ///
  /// If the insert exceeds maxEntries, the LRU_BOUND eviction runs AFTER the
  /// insert BUT the JUST-INSERTED key is EXEMPT from victim selection (the victim
  /// is the min among the OTHER entries). This is REQUIRED because getOrCreate
  /// returns a live reference: under a backward/reordered `now` the just-inserted
  /// entry would otherwise be the unique minimum and evict itself, dangling the
  /// returned reference. If only the just-inserted entry exists at the cap, it is
  /// kept (no other victim exists).
  ///
  /// CAVEAT: the returned reference remains valid across a re-entrant onEvict
  /// callback (even one that inserts and rehashes) because it is a reference to a
  /// stable node, not an iterator. The one way to dangle it is for the callback
  /// to erase the just-created key itself, which is pathological (erasing a key
  /// mid-creation) and outside the callback contract.
  Value &getOrCreate(const Key &key, const FactoryFn &makeValue, TimePoint now)
  {
    auto it = _map.find(key);
    if (it != _map.end())
    {
      it->second.lastActivity = now;
      return it->second.value;
    }
    auto res = _map.emplace(key, Node{makeValue(), now, _seqCounter++});
    // Bind the mapped reference BEFORE enforceBound. enforceBound may fire an
    // onEvict(LRU_BOUND) callback that re-enters the map and inserts; an insert
    // can rehash the table, and a rehash invalidates all ITERATORS (including
    // res.first) while leaving REFERENCES to elements valid. Returning through
    // res.first after the callback would be UB; returning the pre-bound
    // reference is safe. The just-inserted key is exempt from eviction, so this
    // reference is never the victim.
    Value &ref = res.first->second.value;
    enforceBound(res.first);
    return ref;
  }

  /// Lookup WITHOUT refreshing lastActivity (read-only inspection that must not
  /// extend the idle timer). nullptr on miss.
  const Value *peek(const Key &key) const
  {
    auto it = _map.find(key);
    return it == _map.end() ? nullptr : &it->second.value;
  }

  /// Refresh lastActivity = now without returning the value; false on miss.
  bool touch(const Key &key, TimePoint now)
  {
    auto it = _map.find(key);
    if (it == _map.end())
    {
      return false;
    }
    it->second.lastActivity = now;
    return true;
  }

  /// SILENT removal (does NOT fire onEvict). true if the key was present.
  bool erase(const Key &key) { return _map.erase(key) > 0; }

  /// O(n) value scan: evict every entry with (now - lastActivity) > idleTimeout
  /// (STRICT >), copy-then-invoke onEvict(IDLE_TIMEOUT) per victim in the defined
  /// (lastActivity, insertSeq) order with per-victim exception isolation.
  /// Backward-now safe: a negative delta never satisfies the strict-greater test.
  /// Returns the number of entries evicted.
  std::size_t sweepExpired(TimePoint now)
  {
    std::vector<Victim> victims;
    victims.reserve(_map.size()); // upper bound: worst case every entry expires
    for (auto it = _map.begin(); it != _map.end();)
    {
      const Duration idle = now - it->second.lastActivity;
      if (idle > _idleTimeout)
      {
        victims.push_back(makeVictim(it->first, it->second));
        it = _map.erase(it);
      }
      else
      {
        ++it;
      }
    }
    fireVictims(victims, EvictReason::IDLE_TIMEOUT);
    return victims.size();
  }

  /// End-of-capture flush: remove EVERY entry, then fire onEvict(DRAIN) for each
  /// (copy-then-invoke, per-victim exception isolation) in the defined order.
  /// This prevents trailing-entry loss. A second call on an empty map is a no-op.
  /// Returns the number of entries drained.
  std::size_t drainAll()
  {
    std::vector<Victim> victims;
    victims.reserve(_map.size());
    for (auto &kv : _map)
    {
      victims.push_back(makeVictim(kv.first, kv.second));
    }
    _map.clear();
    fireVictims(victims, EvictReason::DRAIN);
    return victims.size();
  }

  /// Read-only iteration; fn has signature void(const Key&, const Value&) and
  /// does NOT refresh lastActivity.
  template <typename Fn>
  void forEach(Fn &&fn) const
  {
    for (const auto &kv : _map)
    {
      fn(kv.first, kv.second.value);
    }
  }

  std::size_t size() const noexcept { return _map.size(); }
  bool empty() const noexcept { return _map.empty(); }
  bool contains(const Key &key) const { return _map.find(key) != _map.end(); }

private:
  struct Node
  {
    Value value;
    TimePoint lastActivity;
    std::uint64_t insertSeq;
  };

  using MapType = std::unordered_map<Key, Node>;

  /// A collected eviction victim: owns a COPY of the Key (so the const Key& given
  /// to onEvict never references an erased node) plus the moved-out value and the
  /// ordering fields.
  struct Victim
  {
    Key key;
    Value value;
    TimePoint lastActivity;
    std::uint64_t insertSeq;
  };

  /// Collect one entry as a Victim: copy the Key (so the const Key& given to
  /// onEvict never references an erased node) and move the value out. Shared by
  /// all three eviction paths.
  static Victim makeVictim(const Key &key, Node &node)
  {
    return Victim{key, std::move(node.value), node.lastActivity, node.insertSeq};
  }

  /// Strict weak ordering by (lastActivity, then insertSeq). Used to pick the
  /// LRU_BOUND victim and to order sweep/drain callbacks deterministically.
  static bool lessActivity(const TimePoint &aTime, std::uint64_t aSeq, const TimePoint &bTime,
                           std::uint64_t bSeq)
  {
    if (aTime < bTime)
    {
      return true;
    }
    if (bTime < aTime)
    {
      return false;
    }
    return aSeq < bSeq;
  }

  /// Invoke onEvict for one victim with exception isolation (both a std and a
  /// non-std throw are caught so neither escapes to abort a loop). An empty
  /// onEvict is a clean no-callback path.
  void fireOne(const Key &key, Value &&value, EvictReason reason)
  {
    if (!_onEvict)
    {
      return;
    }
    try
    {
      _onEvict(key, std::move(value), reason);
    }
    catch (const std::exception &)
    {
      // Caught-and-isolated per designPrinciples COPY-THEN-INVOKE: one victim's
      // throwing callback must not abort eviction of the rest.
    }
    catch (...)
    {
      // A non-std throw must not escape either.
    }
  }

  /// Sort collected victims into the defined order and fire each callback
  /// copy-then-invoke (all map mutation is already done before any callback).
  void fireVictims(std::vector<Victim> &victims, EvictReason reason)
  {
    std::sort(victims.begin(), victims.end(),
              [](const Victim &a, const Victim &b)
              { return lessActivity(a.lastActivity, a.insertSeq, b.lastActivity, b.insertSeq); });
    for (auto &v : victims)
    {
      fireOne(v.key, std::move(v.value), reason);
    }
  }

  /// After an insert that may exceed maxEntries, evict the single
  /// min-(lastActivity, insertSeq) victim by scan, copy-then-invoke
  /// onEvict(LRU_BOUND). `exempt` (when != end()) is excluded from victim
  /// selection so getOrCreate's just-inserted, about-to-be-returned entry can
  /// never be its own victim; put() passes end() and tolerates self-eviction.
  void enforceBound(typename MapType::iterator exempt)
  {
    if (!_maxEntries.has_value() || _map.size() <= *_maxEntries)
    {
      return;
    }
    auto victim = _map.end();
    for (auto it = _map.begin(); it != _map.end(); ++it)
    {
      if (it == exempt)
      {
        continue;
      }
      if (victim == _map.end() ||
          lessActivity(it->second.lastActivity, it->second.insertSeq, victim->second.lastActivity,
                       victim->second.insertSeq))
      {
        victim = it;
      }
    }
    if (victim == _map.end())
    {
      // Defensive/unreachable under the current invariant: maxEntries >= 1
      // (ctor-enforced, never mutated) plus the size() > *_maxEntries guard above
      // together guarantee at least one non-exempt entry exists here, so the scan
      // always sets `victim`. The "just-inserted entry alone at the cap" case is
      // handled by the early return at the top of this function, not here. Kept
      // as a guard against a UB dereference of `victim` should that invariant
      // ever be weakened by a future edit.
      return;
    }
    Victim v = makeVictim(victim->first, victim->second);
    _map.erase(victim);
    fireOne(v.key, std::move(v.value), EvictReason::LRU_BOUND);
  }

  Duration _idleTimeout;
  EvictionCallback _onEvict;
  std::optional<std::size_t> _maxEntries;
  MapType _map;
  std::uint64_t _seqCounter{0};
};

} // namespace util
} // namespace iora
