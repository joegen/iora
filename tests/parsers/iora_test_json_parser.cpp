// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#define CATCH_CONFIG_MAIN
#include "iora/parsers/json.hpp"
#include <atomic>
#include <catch2/catch.hpp>
#include <chrono>
#include <cmath>
#include <limits>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace iora::parsers;

namespace
{

/// \brief Generate random strings for fuzzing
std::string generateRandomString(std::mt19937 &rng, size_t maxLength = 100)
{
  std::uniform_int_distribution<size_t> lengthDist(0, maxLength);
  std::uniform_int_distribution<char> charDist(32, 126); // Printable ASCII

  size_t length = lengthDist(rng);
  std::string result;
  result.reserve(length);

  for (size_t i = 0; i < length; ++i)
  {
    result.push_back(charDist(rng));
  }
  return result;
}

/// \brief Generate random JSON-like strings with varying validity
std::string generateRandomJsonLike(std::mt19937 &rng)
{
  std::vector<std::string> templates = {
    R"({"key": "value"})",
    R"([1, 2, 3])",
    R"({"nested": {"key": [1, 2, 3]}})",
    R"(null)",
    R"(true)",
    R"(false)",
    R"(123)",
    R"(-456.789)",
    R"("string")",
    R"({"malformed": })",   // Invalid
    R"([1, 2, 3,])",        // Invalid trailing comma
    R"({"key": value})",    // Unquoted value
    R"({key: "value"})",    // Unquoted key
    R"({"key": "value")",   // Missing closing brace
    R"({"key": "value"}})", // Extra closing brace
    ""                      // Empty string
  };

  std::uniform_int_distribution<size_t> dist(0, templates.size() - 1);
  return templates[dist(rng)];
}

} // anonymous namespace

TEST_CASE("JSON Parser - Basic Type Construction", "[json][basic]")
{
  SECTION("Null construction")
  {
    Json j;
    REQUIRE(j.is_null());
    REQUIRE_FALSE(j.is_boolean());
    REQUIRE_FALSE(j.is_number());
    REQUIRE_FALSE(j.is_string());
    REQUIRE_FALSE(j.is_array());
    REQUIRE_FALSE(j.is_object());
  }

  SECTION("Boolean construction")
  {
    Json jTrue(true);
    Json jFalse(false);

    REQUIRE(jTrue.is_boolean());
    REQUIRE(jFalse.is_boolean());
    REQUIRE(jTrue.get<bool>() == true);
    REQUIRE(jFalse.get<bool>() == false);
  }

  SECTION("Number construction")
  {
    Json jInt(42);
    Json jDouble(3.14159);
    Json jNegative(-123);

    REQUIRE(jInt.is_number());
    REQUIRE(jDouble.is_number());
    REQUIRE(jNegative.is_number());

    REQUIRE(jInt.get<int>() == 42);
    REQUIRE(jDouble.get<double>() == Approx(3.14159));
    REQUIRE(jNegative.get<int>() == -123);
  }

  SECTION("String construction")
  {
    Json jStr("hello world");
    Json jEmpty("");

    REQUIRE(jStr.is_string());
    REQUIRE(jEmpty.is_string());
    REQUIRE(jStr.get<std::string>() == "hello world");
    REQUIRE(jEmpty.get<std::string>() == "");
  }

  SECTION("Array construction")
  {
    Json jArr = Json::array();
    REQUIRE(jArr.is_array());
    REQUIRE(jArr.empty());
    REQUIRE(jArr.size() == 0);
  }

  SECTION("Object construction")
  {
    Json jObj = Json::object();
    REQUIRE(jObj.is_object());
    REQUIRE(jObj.empty());
    REQUIRE(jObj.size() == 0);
  }
}

TEST_CASE("JSON Parser - Constructor Disambiguation", "[json][constructors]")
{
  SECTION("Parentheses vs brace initialization")
  {
    // These should create proper objects/arrays, not use initializer_list
    // constructor
    Json objParens = Json::object();
    Json arrParens = Json::array();

    REQUIRE(objParens.is_object());
    REQUIRE(arrParens.is_array());

    // Test explicit construction
    Json explicitInt(42);
    Json explicitStr("test");
    Json explicitBool(true);

    REQUIRE(explicitInt.is_number());
    REQUIRE(explicitStr.is_string());
    REQUIRE(explicitBool.is_boolean());
  }

  SECTION("Copy and move semantics")
  {
    Json original = Json::object();
    original["key"] = "value";

    Json copied(original);
    Json moved(std::move(original));

    REQUIRE(copied.is_object());
    REQUIRE(moved.is_object());
    REQUIRE(copied["key"].get<std::string>() == "value");
    REQUIRE(moved["key"].get<std::string>() == "value");
  }
}

TEST_CASE("JSON Parser - Object Operations", "[json][objects]")
{
  SECTION("Key insertion and access")
  {
    Json obj = Json::object();

    obj["string_key"] = "string_value";
    obj["int_key"] = 123;
    obj["bool_key"] = true;
    obj["null_key"] = nullptr;

    REQUIRE(obj.contains("string_key"));
    REQUIRE(obj.contains("int_key"));
    REQUIRE(obj.contains("bool_key"));
    REQUIRE(obj.contains("null_key"));
    REQUIRE_FALSE(obj.contains("nonexistent"));

    REQUIRE(obj["string_key"].get<std::string>() == "string_value");
    REQUIRE(obj["int_key"].get<int>() == 123);
    REQUIRE(obj["bool_key"].get<bool>() == true);
    REQUIRE(obj["null_key"].is_null());
  }

  SECTION("Object size and emptiness")
  {
    Json obj = Json::object();
    REQUIRE(obj.empty());
    REQUIRE(obj.size() == 0);

    obj["key1"] = "value1";
    REQUIRE_FALSE(obj.empty());
    REQUIRE(obj.size() == 1);

    obj["key2"] = "value2";
    REQUIRE(obj.size() == 2);
  }

  SECTION("Object iteration")
  {
    Json obj = Json::object();
    obj["a"] = 1;
    obj["b"] = 2;
    obj["c"] = 3;

    size_t count = 0;
    for (const auto &[key, value] : obj.items())
    {
      REQUIRE(obj.contains(key));
      count++;
    }
    REQUIRE(count == 3);
  }

  SECTION("Nested objects")
  {
    Json root = Json::object();
    Json nested = Json::object();
    nested["inner"] = "value";
    root["outer"] = nested;

    REQUIRE(root["outer"].is_object());
    REQUIRE(root["outer"]["inner"].get<std::string>() == "value");
  }
}

TEST_CASE("JSON Parser - Array Operations", "[json][arrays]")
{
  SECTION("Array insertion and access")
  {
    Json arr = Json::array();

    arr.push_back("string");
    arr.push_back(42);
    arr.push_back(true);
    arr.push_back(nullptr);

    REQUIRE(arr.size() == 4);
    REQUIRE(arr[static_cast<std::size_t>(0)].get<std::string>() == "string");
    REQUIRE(arr[1].get<int>() == 42);
    REQUIRE(arr[2].get<bool>() == true);
    REQUIRE(arr[3].is_null());
  }

  SECTION("Array bounds checking")
  {
    Json arr = Json::array();
    arr.push_back("test");

    REQUIRE(arr[static_cast<std::size_t>(0)].get<std::string>() == "test");

    // Access beyond bounds should not crash but return null
    REQUIRE(arr[10].is_null());
  }

  SECTION("Array iteration")
  {
    Json arr = Json::array();
    for (int i = 0; i < 5; ++i)
    {
      arr.push_back(i);
    }

    size_t index = 0;
    for (const auto &item : arr)
    {
      REQUIRE(item.get<int>() == static_cast<int>(index));
      index++;
    }
    REQUIRE(index == 5);
  }

  SECTION("Mixed type arrays")
  {
    Json arr = Json::array();
    arr.push_back(123);
    arr.push_back("mixed");
    arr.push_back(Json::object());
    arr.push_back(Json::array());

    REQUIRE(arr[static_cast<std::size_t>(0)].is_number());
    REQUIRE(arr[1].is_string());
    REQUIRE(arr[2].is_object());
    REQUIRE(arr[3].is_array());
  }
}

TEST_CASE("JSON Parser - String Parsing", "[json][parsing]")
{
  SECTION("Valid JSON parsing")
  {
    SECTION("Simple values")
    {
      REQUIRE(Json::parseString("null").is_null());
      REQUIRE(Json::parseString("true").get<bool>() == true);
      REQUIRE(Json::parseString("false").get<bool>() == false);
      REQUIRE(Json::parseString("42").get<int>() == 42);
      REQUIRE(Json::parseString("-123").get<int>() == -123);
      REQUIRE(Json::parseString("3.14159").get<double>() == Approx(3.14159));
      REQUIRE(Json::parseString("\"hello\"").get<std::string>() == "hello");
    }

    SECTION("Objects")
    {
      auto obj = Json::parseString(R"({"key": "value", "number": 42})");
      REQUIRE(obj.is_object());
      REQUIRE(obj["key"].get<std::string>() == "value");
      REQUIRE(obj["number"].get<int>() == 42);
    }

    SECTION("Arrays")
    {
      auto arr = Json::parseString(R"([1, "two", true, null])");
      REQUIRE(arr.is_array());
      REQUIRE(arr.size() == 4);
      REQUIRE(arr[static_cast<std::size_t>(0)].get<int>() == 1);
      REQUIRE(arr[1].get<std::string>() == "two");
      REQUIRE(arr[2].get<bool>() == true);
      REQUIRE(arr[3].is_null());
    }

    SECTION("Nested structures")
    {
      auto nested = Json::parseString(R"({
        "array": [1, 2, 3],
        "object": {"nested": true},
        "mixed": [{"a": 1}, {"b": 2}]
      })");

      REQUIRE(nested.is_object());
      REQUIRE(nested["array"].is_array());
      REQUIRE(nested["array"].size() == 3);
      REQUIRE(nested["object"]["nested"].get<bool>() == true);
      REQUIRE(nested["mixed"][static_cast<std::size_t>(0)]["a"].get<int>() == 1);
    }
  }

  SECTION("Invalid JSON parsing")
  {
    std::vector<std::string> invalidJson = {
      "",                    // Empty
      "{",                   // Incomplete object
      "}",                   // Unexpected closing
      "[1, 2, 3,]",          // Trailing comma
      R"({"key": })",        // Missing value
      R"({key: "value"})",   // Unquoted key
      R"({"key": value})",   // Unquoted value
      "undefined",           // Invalid literal
      "NaN",                 // Invalid number
      "Infinity",            // Invalid number
      R"("unclosed string)", // Unclosed string
      "[1, 2, 3}",           // Mismatched brackets
      "{1, 2, 3]"            // Mismatched brackets
    };

    for (const auto &invalid : invalidJson)
    {
      REQUIRE_THROWS_AS(Json::parseString(invalid), std::exception);
    }
  }
}

TEST_CASE("JSON Parser - Serialization", "[json][serialization]")
{
  SECTION("Basic value serialization")
  {
    REQUIRE(Json().dump() == "null");
    REQUIRE(Json(true).dump() == "true");
    REQUIRE(Json(false).dump() == "false");
    REQUIRE(Json(42).dump() == "42");
    REQUIRE(Json("hello").dump() == "\"hello\"");
  }

  SECTION("Object serialization")
  {
    Json obj = Json::object();
    obj["key"] = "value";
    obj["number"] = 123;

    std::string serialized = obj.dump();
    auto parsed = Json::parseString(serialized);

    REQUIRE(parsed.is_object());
    REQUIRE(parsed["key"].get<std::string>() == "value");
    REQUIRE(parsed["number"].get<int>() == 123);
  }

  SECTION("Array serialization")
  {
    Json arr = Json::array();
    arr.push_back(1);
    arr.push_back("two");
    arr.push_back(true);

    std::string serialized = arr.dump();
    auto parsed = Json::parseString(serialized);

    REQUIRE(parsed.is_array());
    REQUIRE(parsed.size() == 3);
    REQUIRE(parsed[static_cast<std::size_t>(0)].get<int>() == 1);
    REQUIRE(parsed[1].get<std::string>() == "two");
    REQUIRE(parsed[2].get<bool>() == true);
  }

  SECTION("Round-trip consistency")
  {
    std::vector<std::string> testCases = {R"(null)",
                                          R"(true)",
                                          R"(false)",
                                          R"(42)",
                                          R"(-123.456)",
                                          R"("string with spaces")",
                                          R"([])",
                                          R"({})",
                                          R"([1, 2, 3])",
                                          R"({"a": 1, "b": 2})",
                                          R"({"nested": {"array": [1, 2, {"deep": true}]}})"};

    for (const auto &testCase : testCases)
    {
      auto parsed = Json::parseString(testCase);
      auto serialized = parsed.dump();
      auto reparsed = Json::parseString(serialized);

      // The reparsed should be semantically equivalent (though formatting/order
      // may differ) For objects, check that all keys and values match
      if (parsed.is_object() && reparsed.is_object())
      {
        REQUIRE(parsed.size() == reparsed.size());
        for (const auto &[key, value] : parsed.items())
        {
          REQUIRE(reparsed.contains(key));
          REQUIRE(reparsed[key].dump() == value.dump());
        }
      }
      else
      {
        // For non-objects, dumps should be identical
        REQUIRE(reparsed.dump() == parsed.dump());
      }
    }
  }
}

TEST_CASE("JSON Parser - Type Conversions and Edge Cases", "[json][conversions]")
{
  SECTION("Number precision")
  {
    Json largeInt(std::numeric_limits<std::int64_t>::max());
    Json smallInt(std::numeric_limits<std::int64_t>::min());
    Json largeDouble(1.7976931348623157e+308); // Close to double max
    Json smallDouble(2.2250738585072014e-308); // Close to double min

    REQUIRE(largeInt.is_number());
    REQUIRE(smallInt.is_number());
    REQUIRE(largeDouble.is_number());
    REQUIRE(smallDouble.is_number());
  }

  SECTION("String escaping")
  {
    Json escaped("Line 1\nLine 2\tTab\r\nQuote: \"Hello\"");
    std::string serialized = escaped.dump();
    auto parsed = Json::parseString(serialized);

    REQUIRE(parsed.get<std::string>() == "Line 1\nLine 2\tTab\r\nQuote: \"Hello\"");
  }

  SECTION("Unicode handling")
  {
    Json unicode("Unicode: 🚀 🎉 ñ ü");
    std::string serialized = unicode.dump();
    auto parsed = Json::parseString(serialized);

    REQUIRE(parsed.get<std::string>() == "Unicode: 🚀 🎉 ñ ü");
  }

  SECTION("Empty containers")
  {
    Json emptyObj = Json::object();
    Json emptyArr = Json::array();

    REQUIRE(emptyObj.dump() == "{}");
    REQUIRE(emptyArr.dump() == "[]");

    auto parsedObj = Json::parseString("{}");
    auto parsedArr = Json::parseString("[]");

    REQUIRE(parsedObj.is_object());
    REQUIRE(parsedObj.empty());
    REQUIRE(parsedArr.is_array());
    REQUIRE(parsedArr.empty());
  }
}

TEST_CASE("JSON Parser - Performance and Memory", "[json][performance]")
{
  SECTION("Large object performance")
  {
    Json largeObj = Json::object();

    auto start = std::chrono::high_resolution_clock::now();

    // Create object with 10000 keys
    for (int i = 0; i < 10000; ++i)
    {
      largeObj["key_" + std::to_string(i)] = i;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    REQUIRE(largeObj.size() == 10000);
    REQUIRE(duration.count() < 1000); // Should complete in less than 1 second
  }

  SECTION("Large array performance")
  {
    Json largeArr = Json::array();

    auto start = std::chrono::high_resolution_clock::now();

    // Create array with 100000 elements
    for (int i = 0; i < 100000; ++i)
    {
      largeArr.push_back(i);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    REQUIRE(largeArr.size() == 100000);
    REQUIRE(duration.count() < 1000); // Should complete in less than 1 second
  }

  SECTION("Deep nesting")
  {
    Json root = Json::object();
    Json *current = &root;

    // Create nested structure 100 levels deep
    for (int i = 0; i < 100; ++i)
    {
      (*current)["level"] = i;
      (*current)["next"] = Json::object();
      current = &(*current)["next"];
    }

    // Verify we can serialize and parse deep structures
    std::string serialized = root.dump();
    REQUIRE_NOTHROW(Json::parseString(serialized));
  }
}

TEST_CASE("JSON Parser - Fuzzing Tests", "[json][fuzzing]")
{
  std::random_device rd;
  std::mt19937 rng(rd());

  SECTION("Random string fuzzing")
  {
    // Test 1000 random strings to ensure no crashes
    for (int i = 0; i < 1000; ++i)
    {
      std::string randomStr = generateRandomString(rng);

      // These may throw exceptions, but should not crash
      try
      {
        Json::parseString(randomStr);
      }
      catch (const std::exception &)
      {
        // Expected for invalid JSON
      }
    }
  }

  SECTION("Random JSON-like fuzzing")
  {
    // Test variations of JSON-like strings
    for (int i = 0; i < 500; ++i)
    {
      std::string jsonLike = generateRandomJsonLike(rng);

      try
      {
        auto parsed = Json::parseString(jsonLike);
        // If parsing succeeded, serialization should work
        REQUIRE_NOTHROW(parsed.dump());
      }
      catch (const std::exception &)
      {
        // Expected for invalid JSON
      }
    }
  }

  SECTION("Boundary value fuzzing")
  {
    std::vector<std::string> boundaryTests = {
      std::string(1000000, 'a'),                       // Very long string
      "\"" + std::string(100000, 'x') + "\"",          // Long JSON string
      "[" + std::string(10000, '1') + "]",             // Malformed long array
      "{" + std::string(10000, ' ') + "}",             // Whitespace object
      std::string(1000, '[') + std::string(1000, ']'), // Deep nesting
      "null" + std::string(100000, ' '),               // Trailing whitespace
      std::string(100000, ' ') + "null"                // Leading whitespace
    };

    for (const auto &test : boundaryTests)
    {
      try
      {
        Json::parseString(test);
      }
      catch (const std::exception &)
      {
        // Expected for malformed JSON
      }
    }
  }
}

TEST_CASE("JSON Parser - Thread Safety", "[json][threading]")
{
  SECTION("Concurrent parsing")
  {
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    std::atomic<int> failureCount{0};

    const std::string validJson = R"({"thread": "test", "number": 42})";

    for (int i = 0; i < 10; ++i)
    {
      threads.emplace_back(
        [&, i]()
        {
          try
          {
            for (int j = 0; j < 100; ++j)
            {
              auto parsed = Json::parseString(validJson);
              if (parsed["thread"].get<std::string>() == "test")
              {
                successCount++;
              }
            }
          }
          catch (...)
          {
            failureCount++;
          }
        });
    }

    for (auto &thread : threads)
    {
      thread.join();
    }

    REQUIRE(successCount == 1000);
    REQUIRE(failureCount == 0);
  }

  SECTION("Concurrent object manipulation")
  {
    Json sharedObj = Json::object();
    std::vector<std::thread> threads;
    std::mutex objMutex; // Protect shared object

    for (int i = 0; i < 5; ++i)
    {
      threads.emplace_back(
        [&, i]()
        {
          for (int j = 0; j < 100; ++j)
          {
            std::lock_guard<std::mutex> lock(objMutex);
            sharedObj["thread_" + std::to_string(i) + "_" + std::to_string(j)] = i * 100 + j;
          }
        });
    }

    for (auto &thread : threads)
    {
      thread.join();
    }

    REQUIRE(sharedObj.size() == 500);
  }
}

TEST_CASE("JSON Parser - Error Recovery", "[json][errors]")
{
  SECTION("Graceful error handling")
  {
    std::vector<std::pair<std::string, std::string>> errorCases = {
      {"", "Empty JSON"},
      {"{", "Incomplete object"},
      {"[1,2,", "Incomplete array"},
      {R"({"key": undefined})", "Invalid value"},
      {"1.2.3", "Invalid number"},
      {R"("unclosed)", "Unclosed string"}};

    for (const auto &[input, description] : errorCases)
    {
      bool threwException = false;
      try
      {
        Json::parseString(input);
      }
      catch (const std::exception &e)
      {
        threwException = true;
        // Error message should be meaningful
        REQUIRE(std::string(e.what()).length() > 0);
      }

      REQUIRE(threwException);
    }
  }
}