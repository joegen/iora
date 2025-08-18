#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "test_helpers.hpp"

TEST_CASE("JsonFileStore basic operations", "[state][JsonFileStore]")
{
  const std::string testFile = "test_store.json";
  iora::storage::JsonFileStore store(testFile);

  SECTION("Set and Get")
  {
    store.set("key1", "value1");
    REQUIRE(store.get("key1") == "value1");
  }

  SECTION("Remove")
  {
    store.set("key2", "value2");
    store.remove("key2");
    REQUIRE_FALSE(store.get("key2").has_value());
  }

  std::filesystem::remove(testFile);
}

TEST_CASE("ConcreteStateStore basic operations", "[state][ConcreteStateStore]")
{
  iora::storage::ConcreteStateStore store;

  SECTION("Set and Get (case-insensitive)")
  {
    store.set("KeyA", "Value1");
    store.set("keyb", "Value2");
    REQUIRE(store.get("keya").value() == "Value1");
    REQUIRE(store.get("KEYB").value() == "Value2");
    REQUIRE_FALSE(store.get("missing").has_value());
  }

  SECTION("Remove and Contains")
  {
    store.set("foo", "bar");
    REQUIRE(store.contains("FOO"));
    REQUIRE(store.remove("Foo"));
    REQUIRE_FALSE(store.contains("foo"));
    REQUIRE_FALSE(store.remove("foo"));
  }

  SECTION("Keys, Size, and Empty")
  {
    REQUIRE(store.empty());
    store.set("a", "1");
    store.set("b", "2");
    store.set("c", "3");
    REQUIRE(store.size() == 3);
    auto keys = store.keys();
    REQUIRE(keys.size() == 3);
    REQUIRE_FALSE(store.empty());
  }

  SECTION("Find Keys With Prefix")
  {
    store.set("prefix_one", "x");
    store.set("prefix_two", "y");
    store.set("other", "z");
    auto prefixed = store.findKeysWithPrefix("prefix_");
    REQUIRE(prefixed.size() == 2);
    REQUIRE(std::find(prefixed.begin(), prefixed.end(), "prefix_one") != prefixed.end());
    REQUIRE(std::find(prefixed.begin(), prefixed.end(), "prefix_two") != prefixed.end());
  }

  SECTION("Find Keys By Value")
  {
    store.set("k1", "v");
    store.set("k2", "v");
    store.set("k3", "w");
    auto byValue = store.findKeysByValue("v");
    REQUIRE(byValue.size() == 2);
    REQUIRE(std::find(byValue.begin(), byValue.end(), "k1") != byValue.end());
    REQUIRE(std::find(byValue.begin(), byValue.end(), "k2") != byValue.end());
  }

  SECTION("Find Keys Matching Custom Predicate")
  {
    store.set("apple", "fruit");
    store.set("banana", "fruit");
    store.set("carrot", "vegetable");
    auto matcher = [](const std::string& k) { return k.find('a') != std::string::npos; };
    auto matched = store.findKeysMatching(matcher);
    REQUIRE(matched.size() >= 2);
    REQUIRE(std::find(matched.begin(), matched.end(), "banana") != matched.end());
    REQUIRE(std::find(matched.begin(), matched.end(), "carrot") != matched.end());
  }
}
