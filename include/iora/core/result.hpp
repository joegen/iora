// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace iora {
namespace core {

// Forward declaration for void specialization
template<typename T, typename E = std::string>
class Result;

namespace detail {

/// \brief Wrapper to make T distinct in the variant when T == E.
template<typename T>
struct OkWrapper
{
  T value;
};

/// \brief Wrapper to make E distinct in the variant when T == E.
template<typename E>
struct ErrWrapper
{
  E error;
};

/// \brief Trait to detect Result<T,E> specializations.
template<typename T>
struct IsResult : std::false_type {};

template<typename T, typename E>
struct IsResult<Result<T, E>> : std::true_type {};

template<typename T>
inline constexpr bool is_result_v = IsResult<T>::value;

} // namespace detail

// ══════════════════════════════════════════════════════════════════════════════
// Result<T, E> — Primary Template
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Generic success-or-error type. Holds either a value of type T
/// or an error of type E. Uses OkWrapper/ErrWrapper internally so T == E
/// is allowed (e.g., Result<std::string, std::string>).
///
/// All atomic operations, monadic chains, and accessors have const& and &&
/// overloads for proper move-only type support.
template<typename T, typename E>
class Result
{
public:
  using value_type = T;
  using error_type = E;

  /// \brief Construct a success Result.
  static Result ok(T value)
  {
    return Result(OkTag{}, std::move(value));
  }

  /// \brief Construct an error Result.
  static Result err(E error)
  {
    return Result(ErrTag{}, std::move(error));
  }

  /// \brief True if the Result holds a success value.
  constexpr bool isOk() const noexcept { return _storage.index() == 0; }

  /// \brief True if the Result holds an error value.
  constexpr bool isErr() const noexcept { return _storage.index() == 1; }

  /// \brief Alias for isOk(). Enables: if (auto r = doSomething()) { ... }
  constexpr explicit operator bool() const noexcept { return isOk(); }

  // ── Accessors ────────────────────────────────────────────────────────────

  T& value() &
  {
    return std::get<0>(_storage).value;
  }

  const T& value() const&
  {
    return std::get<0>(_storage).value;
  }

  T&& value() &&
  {
    return std::move(std::get<0>(_storage).value);
  }

  const T&& value() const&&
  {
    return std::move(std::get<0>(_storage).value);
  }

  E& error() &
  {
    return std::get<1>(_storage).error;
  }

  const E& error() const&
  {
    return std::get<1>(_storage).error;
  }

  E&& error() &&
  {
    return std::move(std::get<1>(_storage).error);
  }

  const E&& error() const&&
  {
    return std::move(std::get<1>(_storage).error);
  }

  /// \brief Returns the value if ok, otherwise returns fallback.
  T valueOr(T fallback) const&
  {
    return isOk() ? value() : std::move(fallback);
  }

  /// \brief Returns the value (moved) if ok, otherwise returns fallback.
  T valueOr(T fallback) &&
  {
    return isOk() ? std::move(std::get<0>(_storage).value) : std::move(fallback);
  }

  // ── Monadic Operations ───────────────────────────────────────────────────

  /// \brief If ok, applies fn to the value and wraps in ok().
  /// If fn returns void, returns Result<void, E>.
  /// If err, propagates the error unchanged.
  template<typename F>
  auto map(F&& fn) const& -> Result<std::invoke_result_t<F, const T&>, E>
  {
    using U = std::invoke_result_t<F, const T&>;
    if (isOk())
    {
      if constexpr (std::is_void_v<U>)
      {
        fn(value());
        return Result<void, E>::ok();
      }
      else
      {
        return Result<U, E>::ok(fn(value()));
      }
    }
    return Result<U, E>::err(error());
  }

  template<typename F>
  auto map(F&& fn) && -> Result<std::invoke_result_t<F, T&&>, E>
  {
    using U = std::invoke_result_t<F, T&&>;
    if (isOk())
    {
      if constexpr (std::is_void_v<U>)
      {
        fn(std::move(std::get<0>(_storage).value));
        return Result<void, E>::ok();
      }
      else
      {
        return Result<U, E>::ok(fn(std::move(std::get<0>(_storage).value)));
      }
    }
    return Result<U, E>::err(std::move(std::get<1>(_storage).error));
  }

  /// \brief If ok, applies fn to the value. fn must return Result<U, E>.
  /// If err, propagates the error.
  template<typename F>
  auto andThen(F&& fn) const& -> std::invoke_result_t<F, const T&>
  {
    using ReturnType = std::invoke_result_t<F, const T&>;
    static_assert(detail::is_result_v<ReturnType>,
      "andThen() callback must return a Result<U, E>");
    static_assert(std::is_same_v<typename ReturnType::error_type, E>,
      "andThen() callback must return a Result with the same error type E");
    if (isOk())
    {
      return fn(value());
    }
    return ReturnType::err(error());
  }

  template<typename F>
  auto andThen(F&& fn) && -> std::invoke_result_t<F, T&&>
  {
    using ReturnType = std::invoke_result_t<F, T&&>;
    static_assert(detail::is_result_v<ReturnType>,
      "andThen() callback must return a Result<U, E>");
    static_assert(std::is_same_v<typename ReturnType::error_type, E>,
      "andThen() callback must return a Result with the same error type E");
    if (isOk())
    {
      return fn(std::move(std::get<0>(_storage).value));
    }
    return ReturnType::err(std::move(std::get<1>(_storage).error));
  }

  /// \brief If err, applies fn to the error. If ok, propagates the value.
  template<typename F>
  auto mapError(F&& fn) const& -> Result<T, std::invoke_result_t<F, const E&>>
  {
    using E2 = std::invoke_result_t<F, const E&>;
    if (isErr())
    {
      return Result<T, E2>::err(fn(error()));
    }
    return Result<T, E2>::ok(value());
  }

  template<typename F>
  auto mapError(F&& fn) && -> Result<T, std::invoke_result_t<F, E&&>>
  {
    using E2 = std::invoke_result_t<F, E&&>;
    if (isErr())
    {
      return Result<T, E2>::err(fn(std::move(std::get<1>(_storage).error)));
    }
    return Result<T, E2>::ok(std::move(std::get<0>(_storage).value));
  }

  /// \brief If ok, calls fn(value()) for side effects. Returns *this unchanged.
  template<typename F>
  const Result& inspect(F&& fn) const&
  {
    if (isOk())
    {
      fn(value());
    }
    return *this;
  }

  template<typename F>
  Result& inspect(F&& fn) &
  {
    if (isOk())
    {
      fn(value());
    }
    return *this;
  }

  // ── Comparison ───────────────────────────────────────────────────────────

  template<typename T2 = T, typename E2 = E,
           std::enable_if_t<
             std::is_same_v<T2, T> && std::is_same_v<E2, E> &&
             std::is_invocable_r_v<bool, std::equal_to<>, const T2&, const T2&> &&
             std::is_invocable_r_v<bool, std::equal_to<>, const E2&, const E2&>,
           int> = 0>
  bool operator==(const Result& other) const
  {
    if (isOk() != other.isOk())
    {
      return false;
    }
    if (isOk())
    {
      return value() == other.value();
    }
    return error() == other.error();
  }

  template<typename T2 = T, typename E2 = E,
           std::enable_if_t<
             std::is_same_v<T2, T> && std::is_same_v<E2, E> &&
             std::is_invocable_r_v<bool, std::equal_to<>, const T2&, const T2&> &&
             std::is_invocable_r_v<bool, std::equal_to<>, const E2&, const E2&>,
           int> = 0>
  bool operator!=(const Result& other) const
  {
    return !(*this == other);
  }

private:
  struct OkTag {};
  struct ErrTag {};
  Result(OkTag, T value)
    : _storage(std::in_place_index<0>, detail::OkWrapper<T>{std::move(value)})
  {
  }
  Result(ErrTag, E error)
    : _storage(std::in_place_index<1>, detail::ErrWrapper<E>{std::move(error)})
  {
  }
  std::variant<detail::OkWrapper<T>, detail::ErrWrapper<E>> _storage;
};

// ══════════════════════════════════════════════════════════════════════════════
// Result<void, E> — Void Specialization
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Specialization for operations that succeed with no value or fail
/// with an error. Uses std::variant<std::monostate, E> internally
/// (monostate and E are always distinct — no wrapper needed).
template<typename E>
class Result<void, E>
{
public:
  using value_type = void;
  using error_type = E;

  /// \brief Construct a success Result (no value).
  static Result ok()
  {
    return Result(OkTag{});
  }

  /// \brief Construct an error Result.
  static Result err(E error)
  {
    return Result(ErrTag{}, std::move(error));
  }

  constexpr bool isOk() const noexcept { return _storage.index() == 0; }
  constexpr bool isErr() const noexcept { return _storage.index() == 1; }
  constexpr explicit operator bool() const noexcept { return isOk(); }

  // No value() — void has no value.

  E& error() & { return std::get<1>(_storage); }
  const E& error() const& { return std::get<1>(_storage); }
  E&& error() && { return std::move(std::get<1>(_storage)); }
  const E&& error() const&& { return std::move(std::get<1>(_storage)); }

  /// \brief If ok, calls fn() (no args). fn must return Result<U, E>.
  template<typename F>
  auto andThen(F&& fn) const& -> std::invoke_result_t<F>
  {
    using ReturnType = std::invoke_result_t<F>;
    static_assert(detail::is_result_v<ReturnType>,
      "andThen() callback must return a Result<U, E>");
    static_assert(std::is_same_v<typename ReturnType::error_type, E>,
      "andThen() callback must return a Result with the same error type E");
    if (isOk())
    {
      return fn();
    }
    return ReturnType::err(error());
  }

  template<typename F>
  auto andThen(F&& fn) && -> std::invoke_result_t<F>
  {
    using ReturnType = std::invoke_result_t<F>;
    static_assert(detail::is_result_v<ReturnType>,
      "andThen() callback must return a Result<U, E>");
    static_assert(std::is_same_v<typename ReturnType::error_type, E>,
      "andThen() callback must return a Result with the same error type E");
    if (isOk())
    {
      return fn();
    }
    return ReturnType::err(std::move(std::get<1>(_storage)));
  }

  /// \brief If err, transforms the error. If ok, propagates the ok state.
  template<typename F>
  auto mapError(F&& fn) const& -> Result<void, std::invoke_result_t<F, const E&>>
  {
    using E2 = std::invoke_result_t<F, const E&>;
    if (isErr())
    {
      return Result<void, E2>::err(fn(error()));
    }
    return Result<void, E2>::ok();
  }

  template<typename F>
  auto mapError(F&& fn) && -> Result<void, std::invoke_result_t<F, E&&>>
  {
    using E2 = std::invoke_result_t<F, E&&>;
    if (isErr())
    {
      return Result<void, E2>::err(fn(std::move(std::get<1>(_storage))));
    }
    return Result<void, E2>::ok();
  }

  /// \brief If ok, calls fn() for side effects. Returns *this unchanged.
  template<typename F>
  const Result& inspect(F&& fn) const&
  {
    if (isOk())
    {
      fn();
    }
    return *this;
  }

  template<typename F>
  Result& inspect(F&& fn) &
  {
    if (isOk())
    {
      fn();
    }
    return *this;
  }

  // ── Comparison ───────────────────────────────────────────────────────────

  template<typename E2 = E,
           std::enable_if_t<
             std::is_same_v<E2, E> &&
             std::is_invocable_r_v<bool, std::equal_to<>, const E2&, const E2&>,
           int> = 0>
  bool operator==(const Result& other) const
  {
    if (isOk() != other.isOk())
    {
      return false;
    }
    if (isOk())
    {
      return true; // both ok, no value to compare
    }
    return error() == other.error();
  }

  template<typename E2 = E,
           std::enable_if_t<
             std::is_same_v<E2, E> &&
             std::is_invocable_r_v<bool, std::equal_to<>, const E2&, const E2&>,
           int> = 0>
  bool operator!=(const Result& other) const
  {
    return !(*this == other);
  }

private:
  struct OkTag {};
  struct ErrTag {};
  Result(OkTag)
    : _storage(std::in_place_index<0>, std::monostate{})
  {
  }
  Result(ErrTag, E error)
    : _storage(std::in_place_index<1>, std::move(error))
  {
  }
  std::variant<std::monostate, E> _storage;
};

} // namespace core
} // namespace iora
