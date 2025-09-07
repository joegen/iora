// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace iora
{
namespace parsers
{
namespace toml
{

class table;
class array;
class node;

using value_type = std::variant<std::monostate, int64_t, double, bool, std::string,
                                std::shared_ptr<table>, std::shared_ptr<array>>;

class array
{
public:
  using container_type = std::vector<value_type>;
  using iterator = container_type::iterator;
  using const_iterator = container_type::const_iterator;

  void push_back(const value_type &val) { _values.push_back(val); }
  void push_back(value_type &&val) { _values.push_back(std::move(val)); }

  size_t size() const { return _values.size(); }
  bool empty() const { return _values.empty(); }

  iterator begin() { return _values.begin(); }
  iterator end() { return _values.end(); }
  const_iterator begin() const { return _values.begin(); }
  const_iterator end() const { return _values.end(); }

  const value_type &operator[](size_t idx) const { return _values[idx]; }
  value_type &operator[](size_t idx) { return _values[idx]; }

private:
  container_type _values;
};

class node
{
public:
  node() = default;
  node(const value_type &val) : _value(val) {}
  node(value_type &&val) : _value(std::move(val)) {}

  bool is_value() const { return !std::holds_alternative<std::monostate>(_value); }

  bool is_string() const { return std::holds_alternative<std::string>(_value); }

  bool is_integer() const { return std::holds_alternative<int64_t>(_value); }

  bool is_floating_point() const { return std::holds_alternative<double>(_value); }

  bool is_boolean() const { return std::holds_alternative<bool>(_value); }

  bool is_array() const { return std::holds_alternative<std::shared_ptr<array>>(_value); }

  bool is_table() const { return std::holds_alternative<std::shared_ptr<table>>(_value); }

  template <typename T> std::optional<T> as() const
  {
    if constexpr (std::is_same_v<T, int64_t>)
    {
      if (auto *val = std::get_if<int64_t>(&_value))
        return *val;
    }
    else if constexpr (std::is_same_v<T, double>)
    {
      if (auto *val = std::get_if<double>(&_value))
        return *val;
      if (auto *val = std::get_if<int64_t>(&_value))
        return static_cast<double>(*val);
    }
    else if constexpr (std::is_same_v<T, bool>)
    {
      if (auto *val = std::get_if<bool>(&_value))
        return *val;
    }
    else if constexpr (std::is_same_v<T, std::string>)
    {
      if (auto *val = std::get_if<std::string>(&_value))
        return *val;
    }
    return std::nullopt;
  }

  template <typename T> std::optional<T> value() const { return as<T>(); }

  array *as_array()
  {
    if (auto *val = std::get_if<std::shared_ptr<array>>(&_value))
      return val->get();
    return nullptr;
  }

  const array *as_array() const
  {
    if (auto *val = std::get_if<std::shared_ptr<array>>(&_value))
      return val->get();
    return nullptr;
  }

  table *as_table()
  {
    if (auto *val = std::get_if<std::shared_ptr<table>>(&_value))
      return val->get();
    return nullptr;
  }

  const table *as_table() const
  {
    if (auto *val = std::get_if<std::shared_ptr<table>>(&_value))
      return val->get();
    return nullptr;
  }

  explicit operator bool() const { return !std::holds_alternative<std::monostate>(_value); }

  const value_type &get_value() const { return _value; }
  value_type &get_value() { return _value; }

private:
  value_type _value;
};

class table
{
public:
  using container_type = std::unordered_map<std::string, node>;
  using iterator = container_type::iterator;
  using const_iterator = container_type::const_iterator;

  bool contains(const std::string &key) const { return _values.find(key) != _values.end(); }

  bool empty() const { return _values.empty(); }

  size_t size() const { return _values.size(); }

  node &operator[](const std::string &key) { return _values[key]; }

  const node &at(const std::string &key) const
  {
    auto it = _values.find(key);
    if (it == _values.end())
      throw std::out_of_range("Key not found: " + key);
    return it->second;
  }

  node at_path(const std::string &dottedPath) const
  {
    std::vector<std::string> parts;
    std::stringstream ss(dottedPath);
    std::string part;
    while (std::getline(ss, part, '.'))
      parts.push_back(part);

    if (parts.empty())
      return node();

    const table *current = this;
    for (size_t i = 0; i < parts.size(); ++i)
    {
      auto it = current->_values.find(parts[i]);
      if (it == current->_values.end())
        return node();

      if (i == parts.size() - 1)
        return it->second;

      current = it->second.as_table();
      if (!current)
        return node();
    }
    return node();
  }

  iterator begin() { return _values.begin(); }
  iterator end() { return _values.end(); }
  const_iterator begin() const { return _values.begin(); }
  const_iterator end() const { return _values.end(); }

  void insert(const std::string &key, const node &value) { _values[key] = value; }

  void insert(const std::string &key, node &&value) { _values[key] = std::move(value); }

private:
  container_type _values;
};

class parser
{
public:
  explicit parser(const std::string &input) : _input(input), _pos(0) {}

  table parse()
  {
    table root;
    table *currentTable = &root;
    std::string currentSection;

    while (!isEnd())
    {
      skipWhitespaceAndComments();
      if (isEnd())
        break;

      if (peek() == '[')
      {
        currentSection = parseSection();
        currentTable = ensureTable(&root, currentSection);
      }
      else
      {
        auto [key, value] = parseKeyValue();
        if (!key.empty())
          currentTable->insert(key, value);
      }
      skipWhitespaceAndComments();
    }
    return root;
  }

private:
  std::string _input;
  size_t _pos;

  bool isEnd() const { return _pos >= _input.size(); }
  char peek() const { return isEnd() ? '\0' : _input[_pos]; }
  char peek(size_t offset) const
  {
    size_t p = _pos + offset;
    return p >= _input.size() ? '\0' : _input[p];
  }
  char advance() { return isEnd() ? '\0' : _input[_pos++]; }

  void skipWhitespace()
  {
    while (!isEnd() && std::isspace(peek()) && peek() != '\n')
      advance();
  }

  void skipWhitespaceAndNewlines()
  {
    while (!isEnd() && std::isspace(peek()))
      advance();
  }

  void skipWhitespaceAndComments()
  {
    while (!isEnd())
    {
      skipWhitespaceAndNewlines();
      if (peek() == '#')
      {
        while (!isEnd() && peek() != '\n')
          advance();
      }
      else
      {
        break;
      }
    }
  }

  std::string parseSection()
  {
    advance(); // skip '['
    std::string section;
    while (!isEnd() && peek() != ']')
    {
      section += advance();
    }
    if (peek() != ']')
      throw std::runtime_error("Unterminated section");
    advance(); // skip ']'
    return section;
  }

  std::pair<std::string, node> parseKeyValue()
  {
    std::string key = parseKey();
    if (key.empty())
      return {"", node()};

    skipWhitespace();
    if (peek() != '=')
      throw std::runtime_error("Expected '=' after key");
    advance();
    skipWhitespace();

    node value = parseValue();
    return {key, value};
  }

  std::string parseKey()
  {
    std::string key;
    while (!isEnd() && (std::isalnum(peek()) || peek() == '_' || peek() == '-' || peek() == '.'))
    {
      key += advance();
    }
    return key;
  }

  node parseValue()
  {
    skipWhitespace();
    char c = peek();

    if (c == '"' || c == '\'')
      return node(parseString());
    else if (c == '[')
      return node(parseArray());
    else if (c == 't' || c == 'f')
      return node(parseBool());
    else if (c == '+' || c == '-' || std::isdigit(c))
      return node(parseNumber());
    else
      throw std::runtime_error("Invalid value");
  }

  std::string parseString()
  {
    char quote = advance();
    std::string str;
    while (!isEnd() && peek() != quote)
    {
      if (peek() == '\\')
      {
        advance();
        char c = advance();
        switch (c)
        {
        case 'n':
          str += '\n';
          break;
        case 't':
          str += '\t';
          break;
        case 'r':
          str += '\r';
          break;
        case '\\':
          str += '\\';
          break;
        case '"':
          str += '"';
          break;
        case '\'':
          str += '\'';
          break;
        default:
          str += c;
        }
      }
      else
      {
        str += advance();
      }
    }
    if (peek() != quote)
      throw std::runtime_error("Unterminated string");
    advance();
    return str;
  }

  value_type parseArray()
  {
    advance(); // skip '['
    auto arr = std::make_shared<array>();
    skipWhitespaceAndNewlines();

    while (!isEnd() && peek() != ']')
    {
      arr->push_back(parseValue().get_value());
      skipWhitespaceAndNewlines();
      if (peek() == ',')
      {
        advance();
        skipWhitespaceAndNewlines();
      }
    }

    if (peek() != ']')
      throw std::runtime_error("Unterminated array");
    advance();
    return arr;
  }

  bool parseBool()
  {
    std::string word;
    while (!isEnd() && std::isalpha(peek()))
      word += advance();

    if (word == "true")
      return true;
    if (word == "false")
      return false;
    throw std::runtime_error("Invalid boolean value: " + word);
  }

  value_type parseNumber()
  {
    std::string num;
    bool isFloat = false;

    if (peek() == '+' || peek() == '-')
      num += advance();

    while (!isEnd() && (std::isdigit(peek()) || peek() == '.' || peek() == 'e' || peek() == 'E' ||
                        peek() == '+' || peek() == '-'))
    {
      if (peek() == '.' || peek() == 'e' || peek() == 'E')
        isFloat = true;
      num += advance();
    }

    if (isFloat)
    {
      return std::stod(num);
    }
    else
    {
      return static_cast<int64_t>(std::stoll(num));
    }
  }

  table *ensureTable(table *root, const std::string &path)
  {
    std::vector<std::string> parts;
    std::stringstream ss(path);
    std::string part;
    while (std::getline(ss, part, '.'))
      parts.push_back(part);

    table *current = root;
    for (const auto &key : parts)
    {
      if (!current->contains(key))
      {
        current->insert(key, node(std::make_shared<table>()));
      }
      current = current->operator[](key).as_table();
      if (!current)
        throw std::runtime_error("Invalid table path: " + path);
    }
    return current;
  }
};

inline table parse_file(const std::string &filename)
{
  std::ifstream file(filename);
  if (!file.is_open())
    throw std::runtime_error("Cannot open file: " + filename);

  std::stringstream buffer;
  buffer << file.rdbuf();

  parser p(buffer.str());
  return p.parse();
}

inline table parse(const std::string &tomlString)
{
  parser p(tomlString);
  return p.parse();
}

class serializer
{
public:
  static std::string serialize(const table &tbl)
  {
    std::ostringstream os;
    serializeTable(os, tbl, "");
    return os.str();
  }

  static void write_file(const std::string &filename, const table &tbl)
  {
    std::ofstream file(filename);
    if (!file.is_open())
      throw std::runtime_error("Cannot open file for writing: " + filename);
    file << serialize(tbl);
  }

private:
  static void serializeTable(std::ostringstream &os, const table &tbl, const std::string &prefix)
  {
    std::vector<std::pair<std::string, node>> simpleValues;
    std::vector<std::pair<std::string, node>> tables;

    for (const auto &[key, value] : tbl)
    {
      if (value.is_table())
        tables.push_back({key, value});
      else
        simpleValues.push_back({key, value});
    }

    std::sort(simpleValues.begin(), simpleValues.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });
    std::sort(tables.begin(), tables.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });

    if (!prefix.empty() && !simpleValues.empty())
    {
      os << "[" << prefix << "]\n";
    }

    for (const auto &[key, value] : simpleValues)
    {
      os << key << " = ";
      serializeValue(os, value);
      os << "\n";
    }

    if (!simpleValues.empty() && !tables.empty())
      os << "\n";

    for (const auto &[key, value] : tables)
    {
      std::string newPrefix = prefix.empty() ? key : prefix + "." + key;
      if (auto *tbl = value.as_table())
      {
        serializeTable(os, *tbl, newPrefix);
      }
    }
  }

  static void serializeValue(std::ostringstream &os, const node &n)
  {
    if (n.is_string())
    {
      os << '"' << escapeString(*n.as<std::string>()) << '"';
    }
    else if (n.is_integer())
    {
      os << *n.as<int64_t>();
    }
    else if (n.is_floating_point())
    {
      os << std::setprecision(15) << *n.as<double>();
    }
    else if (n.is_boolean())
    {
      os << (*n.as<bool>() ? "true" : "false");
    }
    else if (n.is_array())
    {
      os << "[";
      bool first = true;
      for (const auto &elem : *n.as_array())
      {
        if (!first)
          os << ", ";
        first = false;
        serializeValueType(os, elem);
      }
      os << "]";
    }
  }

  static void serializeValueType(std::ostringstream &os, const value_type &val)
  {
    if (auto *s = std::get_if<std::string>(&val))
    {
      os << '"' << escapeString(*s) << '"';
    }
    else if (auto *i = std::get_if<int64_t>(&val))
    {
      os << *i;
    }
    else if (auto *d = std::get_if<double>(&val))
    {
      os << std::setprecision(15) << *d;
    }
    else if (auto *b = std::get_if<bool>(&val))
    {
      os << (*b ? "true" : "false");
    }
  }

  static std::string escapeString(const std::string &str)
  {
    std::string result;
    for (char c : str)
    {
      switch (c)
      {
      case '\n':
        result += "\\n";
        break;
      case '\t':
        result += "\\t";
        break;
      case '\r':
        result += "\\r";
        break;
      case '\\':
        result += "\\\\";
        break;
      case '"':
        result += "\\\"";
        break;
      default:
        result += c;
      }
    }
    return result;
  }
};

} // namespace toml
} // namespace parsers
} // namespace iora