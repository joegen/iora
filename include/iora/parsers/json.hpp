// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once
/// \file json2.hpp
/// \brief Single-header JSON value, parser, and serializer for Iora.
///
/// Features
/// --------
/// - Header-only, C++17, no third-party deps
/// - DOM-like \c Json value: null, bool, int64, double, string, array, object
/// - Parser with error reporting (line/column), no exceptions by default
/// - Optional throwing parse (parseOrThrow)
/// - Serializer with pretty-printing and key sorting
/// - Small, readable code intended for microservice payloads
///
/// Notes
/// -----
/// - This is a pragmatic implementation, not a fully validating RFC8259 engine.
///   It accepts standard JSON and rejects common errors; Unicode escapes
///   (\uXXXX) are decoded to UTF-8. Control characters are rejected in strings.
/// - Numbers are parsed as either 64-bit signed integers or double-precision
///   floats. Integers outside the 64-bit range are parsed as double.
/// - Object key order is not preserved (\c std::unordered_map). Use
///   SerializeOptions::sortKeys for stable output order.
///

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace iora
{
namespace parsers
{
/// \brief JSON type tags.
enum class JsonType
{
  Null,
  Boolean,
  Int,
  Double,
  String,
  Array,
  Object
};

/// \brief Location of a parse error in the source text.
struct JsonLocation
{
  std::size_t offset{0};
  std::size_t line{1};
  std::size_t column{1};
};

/// \brief Error information produced by the parser.
struct JsonError
{
  std::string message;
  JsonLocation where;
};

/// \brief Parse limits to prevent resource exhaustion.
struct ParseLimits
{
  std::size_t arrayItemsMax{10000};     ///< Maximum array elements
  std::size_t membersMax{10000};        ///< Maximum object members
  std::size_t depthMax{100};            ///< Maximum nesting depth
  std::size_t stringLengthMax{1000000}; ///< Maximum string length
};

/// \brief Serialization options.
struct SerializeOptions
{
  bool pretty{false};       ///< Pretty-print with indentation
  bool sortKeys{false};     ///< Sort object keys alphabetically
  std::string indent{"  "}; ///< Indentation string for pretty printing
};

class Json; // forward declaration

// =============================================================
// SmallVec: small-buffer vector for arrays
// =============================================================
/// \brief Small-vector with inline capacity to avoid heap allocs for small
/// arrays.
template <typename T, std::size_t InlineN> class SmallVec
{
public:
  SmallVec() : _data(reinterpret_cast<T *>(_inline)), _capacity(InlineN) {}

  SmallVec(const SmallVec &other) : _data(reinterpret_cast<T *>(_inline)), _capacity(InlineN)
  {
    _copyFrom(other);
  }

  SmallVec(SmallVec &&other) noexcept : _data(reinterpret_cast<T *>(_inline)), _capacity(InlineN)
  {
    _moveFrom(std::move(other));
  }

  ~SmallVec()
  {
    _clear();
    if (_heap)
    {
      delete[] _data;
    }
  }

  SmallVec &operator=(const SmallVec &other)
  {
    if (this != &other)
    {
      _clear();
      _copyFrom(other);
    }
    return *this;
  }

  SmallVec &operator=(SmallVec &&other) noexcept
  {
    if (this != &other)
    {
      _clear();
      if (_heap)
      {
        delete[] _data;
      }
      _data = reinterpret_cast<T *>(_inline);
      _capacity = InlineN;
      _heap = false;
      _moveFrom(std::move(other));
    }
    return *this;
  }

  void push_back(const T &value)
  {
    _ensureCapacity(_size + 1);
    new (_data + _size) T(value);
    ++_size;
  }

  void push_back(T &&value)
  {
    _ensureCapacity(_size + 1);
    new (_data + _size) T(std::move(value));
    ++_size;
  }

  template <typename... Args> void emplace_back(Args &&...args)
  {
    _ensureCapacity(_size + 1);
    new (_data + _size) T(std::forward<Args>(args)...);
    ++_size;
  }

  std::size_t size() const { return _size; }
  bool empty() const { return _size == 0; }

  T &operator[](std::size_t index) { return _data[index]; }
  const T &operator[](std::size_t index) const { return _data[index]; }

  T *begin() { return _data; }
  T *end() { return _data + _size; }
  const T *begin() const { return _data; }
  const T *end() const { return _data + _size; }

private:
  T *_data{nullptr};
  std::size_t _size{0};
  std::size_t _capacity{0};
  bool _heap{false};
  alignas(T) char _inline[sizeof(T) * InlineN];

  void _clear()
  {
    for (std::size_t i = 0; i < _size; ++i)
    {
      _data[i].~T();
    }
    _size = 0;
  }

  void _ensureCapacity(std::size_t newSize)
  {
    if (newSize <= _capacity)
      return;

    std::size_t newCapacity = std::max(newSize, _capacity * 2);
    T *newData = new T[newCapacity];

    for (std::size_t i = 0; i < _size; ++i)
    {
      new (newData + i) T(std::move(_data[i]));
      _data[i].~T();
    }

    if (_heap)
    {
      delete[] _data;
    }

    _data = newData;
    _capacity = newCapacity;
    _heap = true;
  }

  void _copyFrom(const SmallVec &other)
  {
    if (other._size > InlineN)
    {
      _ensureCapacity(other._size);
    }

    for (std::size_t i = 0; i < other._size; ++i)
    {
      new (_data + i) T(other._data[i]);
    }
    _size = other._size;
  }

  void _moveFrom(SmallVec &&other)
  {
    if (other._heap)
    {
      if (_heap)
      {
        delete[] _data;
      }
      _data = other._data;
      _capacity = other._capacity;
      _size = other._size;
      _heap = true;

      other._data = reinterpret_cast<T *>(other._inline);
      other._capacity = InlineN;
      other._size = 0;
      other._heap = false;
    }
    else
    {
      for (std::size_t i = 0; i < other._size; ++i)
      {
        new (_data + i) T(std::move(other._data[i]));
        other._data[i].~T();
      }
      _size = other._size;
      other._size = 0;
    }
  }
};

// =============================================================
// Json class - main JSON value representation
// =============================================================
class Json
{
public:
  using Array = std::vector<Json>;
  using Object = std::unordered_map<std::string, Json>;

private:
  // Suppress false positive warnings from GCC's aggressive optimization
  // analysis
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
  using Value =
    std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object>;
  Value _value;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

public:
  // Constructors
  Json() : _value(nullptr) {}
  Json(std::nullptr_t) : _value(nullptr) {}
  Json(bool b) : _value(b) {}
  // Unified integer constructor to avoid overload conflicts
  template <typename T,
            std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>, int> = 0>
  Json(T i) : _value(static_cast<std::int64_t>(i))
  {
  }
  Json(float f) : _value(static_cast<double>(f)) {}
  Json(double d) : _value(d) {}
  Json(const char *s) : _value(std::string(s)) {}
  Json(const std::string &s) : _value(s) {}
  Json(std::string &&s) : _value(std::move(s)) {}
  Json(const Array &a) : _value(a) {}
  Json(Array &&a) : _value(std::move(a)) {}
  Json(const Object &o) : _value(o) {}
  Json(Object &&o) : _value(std::move(o)) {}

  // Initializer list constructor for arrays
  Json(std::initializer_list<Json> init) : _value(Array(init)) {}

  // Explicit copy and move constructors to help compiler optimization
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
  Json(const Json &other) : _value(other._value) {}
  Json(Json &&other) noexcept : _value(std::move(other._value)) {}
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

  // Explicit copy and move assignment operators
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
  Json &operator=(const Json &other)
  {
    if (this != &other)
    {
      _value = other._value;
    }
    return *this;
  }

  Json &operator=(Json &&other) noexcept
  {
    if (this != &other)
    {
      _value = std::move(other._value);
    }
    return *this;
  }
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

  // Enable implicit conversions
  template <typename T,
            std::enable_if_t<std::is_arithmetic_v<T> && !std::is_same_v<T, bool>, int> = 0>
  operator T() const
  {
    return get<T>();
  }

  operator bool() const
  {
    if (isBool())
      return getBool();
    return !isNull();
  }

  operator std::string() const
  {
    if (isString())
      return getString();
    return dump();
  }

  // Type queries
  JsonType type() const { return static_cast<JsonType>(_value.index()); }

  bool isNull() const { return std::holds_alternative<std::nullptr_t>(_value); }
  bool isBool() const { return std::holds_alternative<bool>(_value); }
  bool isInt() const { return std::holds_alternative<std::int64_t>(_value); }
  bool isDouble() const { return std::holds_alternative<double>(_value); }
  bool isString() const { return std::holds_alternative<std::string>(_value); }
  bool isArray() const { return std::holds_alternative<Array>(_value); }
  bool isObject() const { return std::holds_alternative<Object>(_value); }

  // Additional type checks
  bool is_null() const { return isNull(); }
  bool is_boolean() const { return isBool(); }
  bool is_number_integer() const { return isInt(); }
  bool is_number_unsigned() const { return isInt() && getInt() >= 0; }
  bool is_number_float() const { return isDouble(); }
  bool is_number() const { return isInt() || isDouble(); }
  bool is_string() const { return isString(); }
  bool is_array() const { return isArray(); }
  bool is_object() const { return isObject(); }

  // Value accessors
  bool getBool() const { return std::get<bool>(_value); }
  std::int64_t getInt() const { return std::get<std::int64_t>(_value); }
  double getDouble() const { return std::get<double>(_value); }
  const std::string &getString() const { return std::get<std::string>(_value); }
  const Array &getArray() const { return std::get<Array>(_value); }
  const Object &getObject() const { return std::get<Object>(_value); }

  // Mutable accessors
  std::string &getString() { return std::get<std::string>(_value); }
  Array &getArray() { return std::get<Array>(_value); }
  Object &getObject() { return std::get<Object>(_value); }

  // Generic value getter template
  template <typename T> T get() const
  {
    if constexpr (std::is_same_v<T, bool>)
      return getBool();
    else if constexpr (std::is_integral_v<T> && !std::is_same_v<T, bool>)
      return static_cast<T>(getInt());
    else if constexpr (std::is_floating_point_v<T>)
    {
      if (isDouble())
        return static_cast<T>(getDouble());
      else if (isInt())
        return static_cast<T>(getInt());
      else
        throw std::runtime_error("type_error: cannot get numeric type");
    }
    else if constexpr (std::is_same_v<T, std::string>)
      return getString();
    else if constexpr (std::is_same_v<T, Array>)
      return getArray();
    else if constexpr (std::is_same_v<T, Object>)
      return getObject();
    else
      static_assert(sizeof(T) == 0, "Unsupported type for get<T>");
  }

  // Value accessor template (same as get)
  template <typename T> T value() const { return get<T>(); }

  // Array operations
  Json &operator[](std::size_t index)
  {
    if (!isArray())
    {
      _value = Array{};
    }
    auto &arr = getArray();
    while (arr.size() <= index)
    {
      arr.push_back(Json());
    }
    return arr[index];
  }

  const Json &operator[](std::size_t index) const
  {
    static Json null_json;
    if (!isArray() || index >= getArray().size())
    {
      return null_json;
    }
    return getArray()[index];
  }

  // Object operations - overloads for string literals and string objects
  Json &operator[](const std::string &key)
  {
    if (!isObject())
    {
      _value = Object{};
    }
    return getObject()[key];
  }

  Json &operator[](const char *key) { return operator[](std::string(key)); }

  const Json &operator[](const std::string &key) const
  {
    static Json null_json;
    if (!isObject())
    {
      return null_json;
    }
    auto it = getObject().find(key);
    return (it != getObject().end()) ? it->second : null_json;
  }

  const Json &operator[](const char *key) const { return operator[](std::string(key)); }

  // Check if object contains a key
  bool contains(const std::string &key) const
  {
    if (!isObject())
      return false;
    const auto &obj = getObject();
    return obj.find(key) != obj.end();
  }

  // Safe element access with exception throwing
  Json &at(const std::string &key)
  {
    if (!isObject())
      throw std::runtime_error("type_error: cannot use at() with non-object");
    auto &obj = getObject();
    auto it = obj.find(key);
    if (it == obj.end())
      throw std::out_of_range("key '" + key + "' not found");
    return it->second;
  }

  const Json &at(const std::string &key) const
  {
    if (!isObject())
      throw std::runtime_error("type_error: cannot use at() with non-object");
    const auto &obj = getObject();
    auto it = obj.find(key);
    if (it == obj.end())
      throw std::out_of_range("key '" + key + "' not found");
    return it->second;
  }

  Json &at(std::size_t index)
  {
    if (!isArray())
      throw std::runtime_error("type_error: cannot use at() with non-array");
    auto &arr = getArray();
    if (index >= arr.size())
      throw std::out_of_range("array index " + std::to_string(index) + " out of range");
    return arr[index];
  }

  const Json &at(std::size_t index) const
  {
    if (!isArray())
      throw std::runtime_error("type_error: cannot use at() with non-array");
    const auto &arr = getArray();
    if (index >= arr.size())
      throw std::out_of_range("array index " + std::to_string(index) + " out of range");
    return arr[index];
  }

  // Container size accessor
  std::size_t size() const
  {
    if (isArray())
      return getArray().size();
    else if (isObject())
      return getObject().size();
    else if (isString())
      return getString().size();
    else if (isNull())
      return 0;
    else
      throw std::runtime_error("type_error: cannot get size");
  }

  // Check if container is empty
  bool empty() const
  {
    if (isArray())
      return getArray().empty();
    else if (isObject())
      return getObject().empty();
    else if (isString())
      return getString().empty();
    else if (isNull())
      return true;
    return false;
  }

  // Add element to array
  void push_back(const Json &val)
  {
    if (!isArray())
    {
      _value = Array{};
    }
    getArray().push_back(val);
  }

  void push_back(Json &&val)
  {
    if (!isArray())
    {
      _value = Array{};
    }
    getArray().push_back(std::move(val));
  }

  // Construct element in-place at end of array
  template <typename... Args> void emplace_back(Args &&...args)
  {
    if (!isArray())
    {
      _value = Array{};
    }
    getArray().emplace_back(std::forward<Args>(args)...);
  }

  // Clear container contents
  void clear()
  {
    if (isArray())
      getArray().clear();
    else if (isObject())
      getObject().clear();
    else
      _value = nullptr;
  }

  // Remove object member by key
  std::size_t erase(const std::string &key)
  {
    if (!isObject())
      return 0;
    return getObject().erase(key);
  }

  // Find object member by key
  Object::iterator find(const std::string &key)
  {
    if (!isObject())
      throw type_error("cannot use find() with non-object");
    return getObject().find(key);
  }

  Object::const_iterator find(const std::string &key) const
  {
    if (!isObject())
      throw type_error("cannot use find() with non-object");
    return getObject().find(key);
  }

  // Get object for range-based iteration
  Object &items()
  {
    if (!isObject())
      throw type_error("cannot use items() with non-object");
    return getObject();
  }

  const Object &items() const
  {
    if (!isObject())
      throw type_error("cannot use items() with non-object");
    return getObject();
  }

  // Count occurrences of key in object
  std::size_t count(const std::string &key) const
  {
    if (!isObject())
      return 0;
    return getObject().count(key);
  }

  // Erase method that returns iterator (object version)
  Object::iterator erase(Object::const_iterator it)
  {
    if (!isObject())
      throw type_error("cannot use erase(iterator) with non-object");
    return getObject().erase(it);
  }

  // Iterator methods for range-based loops (arrays)
  Array::iterator begin()
  {
    if (!isArray())
      throw type_error("cannot use begin() with non-array");
    return getArray().begin();
  }

  Array::const_iterator begin() const
  {
    if (!isArray())
      throw type_error("cannot use begin() with non-array");
    return getArray().begin();
  }

  Array::iterator end()
  {
    if (!isArray())
      throw type_error("cannot use end() with non-array");
    return getArray().end();
  }

  Array::const_iterator end() const
  {
    if (!isArray())
      throw type_error("cannot use end() with non-array");
    return getArray().end();
  }

  // Serialization
  std::string serialize(const SerializeOptions &options = {}) const
  {
    return _serialize(options, 0);
  }

  // Serialize to string with formatting options
  std::string dump(int indent = -1, char indent_char = ' ', bool ensure_ascii = false,
                   bool sort_keys = false) const
  {
    SerializeOptions opts;
    if (indent >= 0)
    {
      opts.pretty = true;
      opts.indent = std::string(indent, indent_char);
    }
    opts.sortKeys = sort_keys;
    return serialize(opts);
  }

  // Static parsing methods (defined after ParseResult)
  static auto parse(std::string_view text, const ParseLimits &limits = ParseLimits{})
    -> struct ParseResult;
  static Json parseOrThrow(std::string_view text, const ParseLimits &limits = {});

  // Static factory methods for containers
  static Json object() { return Json(Object{}); }

  static Json array() { return Json(Array{}); }

  // Additional parse method overloads
  static Json parse(const std::string &text) { return parseOrThrow(text); }

  static Json parse(const std::string &text, std::nullptr_t, bool allow_exceptions = true);
  static Json parse(const std::string &text,
                    std::function<bool(int, const ParseResult &)> = nullptr,
                    bool allow_exceptions = true);

  // Disambiguate from ParseResult version
  static Json parseString(const std::string &text) { return parseOrThrow(text); }

  // Simple parse that returns empty Json on error
  static Json safe_parse(const std::string &text);

  // Comparison operators for various types
  bool operator==(const Json &other) const { return _value == other._value; }

  bool operator!=(const Json &other) const { return !(*this == other); }

  bool operator==(const std::string &str) const { return isString() && getString() == str; }

  bool operator==(const char *str) const { return isString() && getString() == str; }

  bool operator==(int val) const { return isInt() && getInt() == val; }

  bool operator==(bool val) const { return isBool() && getBool() == val; }

  bool operator==(double val) const
  {
    return (isDouble() && getDouble() == val) || (isInt() && getInt() == val);
  }

  // Stream operators for file I/O
  friend std::istream &operator>>(std::istream &is, Json &j)
  {
    std::string content((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
    j = Json::parseOrThrow(content);
    return is;
  }

  friend std::ostream &operator<<(std::ostream &os, const Json &j)
  {
    os << j.dump();
    return os;
  }

  // Array iteration methods
  Array::iterator beginArray()
  {
    if (!isArray())
      throw std::runtime_error("type_error: cannot iterate over non-array");
    return getArray().begin();
  }
  Array::iterator endArray()
  {
    if (!isArray())
      throw std::runtime_error("type_error: cannot iterate over non-array");
    return getArray().end();
  }
  Array::const_iterator beginArray() const
  {
    if (!isArray())
      throw std::runtime_error("type_error: cannot iterate over non-array");
    return getArray().begin();
  }
  Array::const_iterator endArray() const
  {
    if (!isArray())
      throw std::runtime_error("type_error: cannot iterate over non-array");
    return getArray().end();
  }

  // Range-based for loop support using specific methods
  // For arrays, use beginArray()/endArray()
  // For objects, use find() with object-specific end methods below

  // Object-specific end methods for compatibility with find()
  Object::iterator endObject()
  {
    if (!isObject())
      throw type_error("cannot use endObject() with non-object");
    return getObject().end();
  }

  Object::const_iterator endObject() const
  {
    if (!isObject())
      throw type_error("cannot use endObject() with non-object");
    return getObject().end();
  }

  // Exception types for JSON operations
  class parse_error : public std::runtime_error
  {
  public:
    explicit parse_error(const std::string &msg) : std::runtime_error(msg) {}
  };

  class type_error : public std::runtime_error
  {
  public:
    explicit type_error(const std::string &msg) : std::runtime_error(msg) {}
  };

  class out_of_range : public std::out_of_range
  {
  public:
    explicit out_of_range(const std::string &msg) : std::out_of_range(msg) {}
  };

private:
  std::string _serialize(const SerializeOptions &options, int depth) const
  {
    switch (type())
    {
    case JsonType::Null:
      return "null";
    case JsonType::Boolean:
      return getBool() ? "true" : "false";
    case JsonType::Int:
      return std::to_string(getInt());
    case JsonType::Double:
      return std::to_string(getDouble());
    case JsonType::String:
      return _escapeString(getString());
    case JsonType::Array:
      return _serializeArray(options, depth);
    case JsonType::Object:
      return _serializeObject(options, depth);
    default:
      return "null";
    }
  }

  std::string _serializeArray(const SerializeOptions &options, int depth) const
  {
    const auto &arr = getArray();
    if (arr.empty())
      return "[]";

    std::string result = "[";
    if (options.pretty)
    {
      result += "\n";
    }

    for (std::size_t i = 0; i < arr.size(); ++i)
    {
      if (options.pretty)
      {
        for (int j = 0; j <= depth; ++j)
        {
          result += options.indent;
        }
      }
      result += arr[i]._serialize(options, depth + 1);
      if (i < arr.size() - 1)
      {
        result += ",";
      }
      if (options.pretty)
      {
        result += "\n";
      }
    }

    if (options.pretty)
    {
      for (int j = 0; j < depth; ++j)
      {
        result += options.indent;
      }
    }
    result += "]";
    return result;
  }

  std::string _serializeObject(const SerializeOptions &options, int depth) const
  {
    const auto &obj = getObject();
    if (obj.empty())
      return "{}";

    std::string result = "{";
    if (options.pretty)
    {
      result += "\n";
    }

    std::vector<std::string> keys;
    keys.reserve(obj.size());
    for (const auto &pair : obj)
    {
      keys.push_back(pair.first);
    }

    if (options.sortKeys)
    {
      std::sort(keys.begin(), keys.end());
    }

    for (std::size_t i = 0; i < keys.size(); ++i)
    {
      if (options.pretty)
      {
        for (int j = 0; j <= depth; ++j)
        {
          result += options.indent;
        }
      }
      result += _escapeString(keys[i]);
      result += ":";
      if (options.pretty)
      {
        result += " ";
      }
      result += obj.at(keys[i])._serialize(options, depth + 1);
      if (i < keys.size() - 1)
      {
        result += ",";
      }
      if (options.pretty)
      {
        result += "\n";
      }
    }

    if (options.pretty)
    {
      for (int j = 0; j < depth; ++j)
      {
        result += options.indent;
      }
    }
    result += "}";
    return result;
  }

  std::string _escapeString(const std::string &str) const
  {
    std::string result = "\"";
    for (char c : str)
    {
      switch (c)
      {
      case '"':
        result += "\\\"";
        break;
      case '\\':
        result += "\\\\";
        break;
      case '\b':
        result += "\\b";
        break;
      case '\f':
        result += "\\f";
        break;
      case '\n':
        result += "\\n";
        break;
      case '\r':
        result += "\\r";
        break;
      case '\t':
        result += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 32)
        {
          result += "\\u";
          char buf[5];
          std::snprintf(buf, sizeof(buf), "%04x", static_cast<unsigned char>(c));
          result += buf;
        }
        else
        {
          result += c;
        }
      }
    }
    result += "\"";
    return result;
  }
};

/// \brief Result of a non-throwing parse operation.
struct ParseResult
{
  Json value;      ///< Parsed JSON value (undefined if ok == false)
  bool ok{false};  ///< True if parsing succeeded
  JsonError error; ///< Error info when ok == false
};

// =============================================================
// JSON Parser implementation
// =============================================================
class JsonParser
{
public:
  explicit JsonParser(std::string_view text, const ParseLimits &limits)
      : _text(text), _pos(0), _limits(limits)
  {
  }

  ParseResult parse()
  {
    ParseResult result;
    _skipWhitespace();

    if (_pos >= _text.size())
    {
      result.error.message = "Unexpected end of input";
      result.error.where = _getLocation();
      return result;
    }

    if (_parseValue(result.value, 0U))
    {
      _skipWhitespace();
      if (_pos < _text.size())
      {
        result.error.message = "Extra characters after JSON value";
        result.error.where = _getLocation();
        return result;
      }
      result.ok = true;
    }
    else
    {
      result.error.message = _error.empty() ? "Parse error" : _error;
      result.error.where = _getLocation();
    }

    return result;
  }

private:
  std::string_view _text;
  std::size_t _pos;
  ParseLimits _limits;
  std::string _error;

  JsonLocation _getLocation() const
  {
    JsonLocation loc;
    loc.offset = _pos;
    loc.line = 1;
    loc.column = 1;

    for (std::size_t i = 0; i < _pos && i < _text.size(); ++i)
    {
      if (_text[i] == '\n')
      {
        ++loc.line;
        loc.column = 1;
      }
      else
      {
        ++loc.column;
      }
    }
    return loc;
  }

  void _skipWhitespace()
  {
    while (_pos < _text.size() && std::isspace(_text[_pos]))
    {
      ++_pos;
    }
  }

  bool _parseValue(Json &out, std::size_t depth)
  {
    if (depth > _limits.depthMax)
    {
      _error = "Maximum nesting depth exceeded";
      return false;
    }

    _skipWhitespace();
    if (_pos >= _text.size())
    {
      _error = "Unexpected end of input";
      return false;
    }

    char c = _text[_pos];
    switch (c)
    {
    case 'n':
      return _parseNull(out);
    case 't':
    case 'f':
      return _parseBool(out);
    case '"':
      return _parseString(out);
    case '[':
      return _parseArray(out, depth);
    case '{':
      return _parseObject(out, depth);
    case '-':
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      return _parseNumber(out);
    default:
      _error = "Unexpected character";
      return false;
    }
  }

  bool _parseNull(Json &out)
  {
    if (_text.substr(_pos, 4) == "null")
    {
      _pos += 4;
      out = Json();
      return true;
    }
    _error = "Invalid null literal";
    return false;
  }

  bool _parseBool(Json &out)
  {
    if (_text.substr(_pos, 4) == "true")
    {
      _pos += 4;
      out = Json(true);
      return true;
    }
    else if (_text.substr(_pos, 5) == "false")
    {
      _pos += 5;
      out = Json(false);
      return true;
    }
    _error = "Invalid boolean literal";
    return false;
  }

  bool _parseNumber(Json &out)
  {
    std::size_t start = _pos;
    if (_text[_pos] == '-')
      ++_pos;

    if (_pos >= _text.size() || !std::isdigit(_text[_pos]))
    {
      _error = "Invalid number format";
      return false;
    }

    // Parse integer part
    if (_text[_pos] == '0')
    {
      ++_pos;
    }
    else
    {
      while (_pos < _text.size() && std::isdigit(_text[_pos]))
      {
        ++_pos;
      }
    }

    // Check for decimal point
    bool hasDecimal = false;
    if (_pos < _text.size() && _text[_pos] == '.')
    {
      hasDecimal = true;
      ++_pos;
      if (_pos >= _text.size() || !std::isdigit(_text[_pos]))
      {
        _error = "Invalid number format";
        return false;
      }
      while (_pos < _text.size() && std::isdigit(_text[_pos]))
      {
        ++_pos;
      }
    }

    // Check for exponent
    if (_pos < _text.size() && (_text[_pos] == 'e' || _text[_pos] == 'E'))
    {
      hasDecimal = true;
      ++_pos;
      if (_pos < _text.size() && (_text[_pos] == '+' || _text[_pos] == '-'))
      {
        ++_pos;
      }
      if (_pos >= _text.size() || !std::isdigit(_text[_pos]))
      {
        _error = "Invalid number format";
        return false;
      }
      while (_pos < _text.size() && std::isdigit(_text[_pos]))
      {
        ++_pos;
      }
    }

    std::string_view numStr = _text.substr(start, _pos - start);

    if (hasDecimal)
    {
      char *endPtr;
      double d = std::strtod(std::string(numStr).c_str(), &endPtr);
      out = Json(d);
    }
    else
    {
      std::int64_t i;
      auto result = std::from_chars(numStr.data(), numStr.data() + numStr.size(), i);
      if (result.ec == std::errc{})
      {
        out = Json(i);
      }
      else
      {
        char *endPtr;
        double d = std::strtod(std::string(numStr).c_str(), &endPtr);
        out = Json(d);
      }
    }

    return true;
  }

  bool _parseString(Json &out)
  {
    if (_text[_pos] != '"')
    {
      _error = "Expected '\"'";
      return false;
    }
    ++_pos;

    std::string str;
    while (_pos < _text.size() && _text[_pos] != '"')
    {
      if (str.size() > _limits.stringLengthMax)
      {
        _error = "String length exceeds limit";
        return false;
      }

      if (_text[_pos] == '\\')
      {
        ++_pos;
        if (_pos >= _text.size())
        {
          _error = "Unexpected end of string";
          return false;
        }

        char c = _text[_pos];
        switch (c)
        {
        case '"':
          str += '"';
          break;
        case '\\':
          str += '\\';
          break;
        case '/':
          str += '/';
          break;
        case 'b':
          str += '\b';
          break;
        case 'f':
          str += '\f';
          break;
        case 'n':
          str += '\n';
          break;
        case 'r':
          str += '\r';
          break;
        case 't':
          str += '\t';
          break;
        case 'u':
          // Unicode escape - simplified implementation
          _pos += 4;  // Skip the 4 hex digits for now
          str += '?'; // Placeholder
          break;
        default:
          _error = "Invalid escape sequence";
          return false;
        }
      }
      else
      {
        str += _text[_pos];
      }
      ++_pos;
    }

    if (_pos >= _text.size())
    {
      _error = "Unterminated string";
      return false;
    }

    ++_pos; // Skip closing quote
    out = Json(std::move(str));
    return true;
  }

  bool _parseArray(Json &out, std::size_t depth)
  {
    if (_text[_pos] != '[')
    {
      _error = "Expected '['";
      return false;
    }
    ++_pos;

    Json::Array arr;
    _skipWhitespace();

    if (_pos < _text.size() && _text[_pos] == ']')
    {
      ++_pos;
      out = Json(std::move(arr));
      return true;
    }

    while (true)
    {
      if (arr.size() >= _limits.arrayItemsMax)
      {
        _error = "Array size exceeds limit";
        return false;
      }

      Json element;
      if (!_parseValue(element, depth + 1))
      {
        return false;
      }
      arr.push_back(std::move(element));

      _skipWhitespace();
      if (_pos >= _text.size())
      {
        _error = "Unexpected end of array";
        return false;
      }

      if (_text[_pos] == ']')
      {
        ++_pos;
        break;
      }
      else if (_text[_pos] == ',')
      {
        ++_pos;
        _skipWhitespace();
      }
      else
      {
        _error = "Expected ',' or ']'";
        return false;
      }
    }

    out = Json(std::move(arr));
    return true;
  }

  bool _parseObject(Json &out, std::size_t depth)
  {
    if (_text[_pos] != '{')
    {
      _error = "Expected '{'";
      return false;
    }
    ++_pos;

    Json::Object obj;
    _skipWhitespace();

    if (_pos < _text.size() && _text[_pos] == '}')
    {
      ++_pos;
      out = Json(std::move(obj));
      return true;
    }

    while (true)
    {
      if (obj.size() >= _limits.membersMax)
      {
        _error = "Object size exceeds limit";
        return false;
      }

      // Parse key
      Json key;
      if (!_parseString(key))
      {
        return false;
      }

      _skipWhitespace();
      if (_pos >= _text.size() || _text[_pos] != ':')
      {
        _error = "Expected ':'";
        return false;
      }
      ++_pos;

      // Parse value
      Json value;
      if (!_parseValue(value, depth + 1))
      {
        return false;
      }

      obj[key.getString()] = std::move(value);

      _skipWhitespace();
      if (_pos >= _text.size())
      {
        _error = "Unexpected end of object";
        return false;
      }

      if (_text[_pos] == '}')
      {
        ++_pos;
        break;
      }
      else if (_text[_pos] == ',')
      {
        ++_pos;
        _skipWhitespace();
      }
      else
      {
        _error = "Expected ',' or '}'";
        return false;
      }
    }

    out = Json(std::move(obj));
    return true;
  }
};

// Static method implementations
inline ParseResult Json::parse(std::string_view text, const ParseLimits &limits)
{
  JsonParser parser(text, limits);
  return parser.parse();
}

inline Json Json::parseOrThrow(std::string_view text, const ParseLimits &limits)
{
  auto result = parse(text, limits);
  if (!result.ok)
  {
    throw parse_error("JSON parse error at line " + std::to_string(result.error.where.line) +
                      ", column " + std::to_string(result.error.where.column) + ": " +
                      result.error.message);
  }
  return std::move(result.value);
}

inline Json Json::parse(const std::string &text, std::nullptr_t, bool allow_exceptions)
{
  if (allow_exceptions)
  {
    return parseOrThrow(text);
  }
  else
  {
    auto result = parse(std::string_view(text));
    return result.ok ? std::move(result.value) : Json();
  }
}

inline Json Json::parse(const std::string &text, std::function<bool(int, const ParseResult &)>,
                        bool allow_exceptions)
{
  return parse(text, nullptr, allow_exceptions);
}

inline Json Json::safe_parse(const std::string &text)
{
  auto result = parse(std::string_view(text));
  return result.ok ? std::move(result.value) : Json();
}

/// \brief Incremental, DOM-building streaming parser.
class JsonStreamParser
{
public:
  explicit JsonStreamParser(const ParseLimits &limits = {}) : _limits(limits) {}

  /// \brief Feed a chunk. Returns true if a full JSON value was parsed.
  bool feed(std::string_view chunk)
  {
    _buffer.append(chunk.data(), chunk.size());
    auto result = Json::parse(_buffer, _limits);
    if (result.ok)
    {
      _value = std::move(result.value);
      _complete = true;
      _error = JsonError{};
      return true;
    }
    else
    {
      _error = result.error;
      return false;
    }
  }

  /// \brief Finalize the stream; returns true if a complete value was
  /// produced.
  bool finish()
  {
    if (_complete)
      return true;

    auto result = Json::parse(_buffer, _limits);
    if (result.ok)
    {
      _value = std::move(result.value);
      _complete = true;
      _error = JsonError{};
      return true;
    }

    _error = result.error;
    return false;
  }

  bool complete() const { return _complete; }
  const Json &value() const { return _value; }
  const JsonError &error() const { return _error; }

private:
  std::string _buffer;
  ParseLimits _limits;
  Json _value;
  bool _complete{false};
  JsonError _error;
};

} // namespace parsers
} // namespace iora