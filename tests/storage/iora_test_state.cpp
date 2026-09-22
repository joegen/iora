#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iterator>
#include <thread>
#include <vector>

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
    auto matcher = [](const std::string &k) { return k.find('a') != std::string::npos; };
    auto matched = store.findKeysMatching(matcher);
    REQUIRE(matched.size() >= 2);
    REQUIRE(std::find(matched.begin(), matched.end(), "banana") != matched.end());
    REQUIRE(std::find(matched.begin(), matched.end(), "carrot") != matched.end());
  }

  // Regression: findKeysMatching runs the predicate OUTSIDE the store lock
  // (copy-then-iterate), so a matcher that re-enters the store must not deadlock
  // on the non-recursive mutex. Before the fix this self-deadlocked.
  SECTION("Find Keys Matching predicate may re-enter the store")
  {
    store.set("alpha", "1");
    store.set("beta", "2");
    store.set("gamma", "3");
    auto reentrant = [&store](const std::string &k)
    { return store.contains(k) && store.get(k).has_value() && k.size() >= 4; };
    auto matched = store.findKeysMatching(reentrant);
    REQUIRE(matched.size() == 3);
  }

  // Regression: case-folding is ASCII-only and unsigned-char-safe (via the
  // shared StringUtils traits) — high bytes (>= 0x80) must not invoke tolower UB.
  SECTION("High-byte keys do not trip tolower UB")
  {
    const std::string hi = std::string("k\xC3\xA9y"); // "kéy" (UTF-8), bytes >= 0x80
    store.set(hi, "v");
    REQUIRE(store.contains(hi));
    REQUIRE(store.get(hi).value() == "v");
  }
}

// Regression: the shared background-flush thread lifecycle must be free of the
// teardown deadlock (join under registryMutex) and the raw-pointer use-after-free
// (flusher dereferencing an erased-but-not-destroyed instance). Rapid concurrent
// create/destroy churn under a tiny flush interval exercises both: a deadlock
// would hang past the ctest timeout; a UAF would crash under the churn.
TEST_CASE("JsonFileStore concurrent lifecycle churn is deadlock/UAF-free",
          "[state][JsonFileStore][concurrency]")
{
  iora::storage::JsonFileStore::setFlushInterval(std::chrono::milliseconds(2));

  constexpr int kThreads = 4;
  constexpr int kPerThread = 40;
  std::atomic<int> done{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreads);

  for (int t = 0; t < kThreads; ++t)
  {
    workers.emplace_back(
      [t, &done]
      {
        for (int i = 0; i < kPerThread; ++i)
        {
          const std::string file =
            "churn_" + std::to_string(t) + "_" + std::to_string(i) + ".json";
          {
            iora::storage::JsonFileStore store(file);
            store.set("k", std::to_string(i));   // mark dirty so a tick flushes it
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
          } // destructor unregisters (possibly stopping the shared thread) + flushes
          std::filesystem::remove(file);
        }
        done.fetch_add(1);
      });
  }

  for (auto &w : workers)
  {
    w.join();
  }
  REQUIRE(done.load() == kThreads);

  // Restore the default interval for any later test in this binary.
  iora::storage::JsonFileStore::setFlushInterval(std::chrono::milliseconds(2000));
}

// Regression: an instance destroyed while OTHER instances keep the shared flush
// thread alive must not be use-after-free'd by an in-flight tick.
TEST_CASE("JsonFileStore multi-instance destroy under a live flush thread",
          "[state][JsonFileStore][concurrency]")
{
  iora::storage::JsonFileStore::setFlushInterval(std::chrono::milliseconds(2));

  // Keeper stays alive for the whole test so the shared flush thread never stops.
  const std::string keeperFile = "keeper.json";
  iora::storage::JsonFileStore keeper(keeperFile);
  keeper.set("keep", "1");

  for (int i = 0; i < 50; ++i)
  {
    const std::string f = "transient_" + std::to_string(i) + ".json";
    {
      iora::storage::JsonFileStore transient(f);
      transient.set("v", std::to_string(i));
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } // transient destroyed while keeper holds the flush thread open
    std::filesystem::remove(f);
  }

  REQUIRE(keeper.get("keep").value() == "1");

  iora::storage::JsonFileStore::setFlushInterval(std::chrono::milliseconds(2000));
  std::filesystem::remove(keeperFile);
}

// Regression: a FAILED write must keep the store dirty so it is retried, never
// silently dropped. Trigger a failure with a missing parent directory, then
// create the directory and flush again -- the second flush can only persist if
// the first (failed) flush retained _dirty. (Checked BEFORE the destructor's own
// flush(), so it isolates the flag behavior from teardown persistence.)
TEST_CASE("JsonFileStore failed write keeps the store dirty (retried, not dropped)",
          "[state][JsonFileStore]")
{
  namespace fs = std::filesystem;
  const auto base = fs::temp_directory_path() / "iora_jfs_med_a";
  const auto missingParent = base / "sub";
  const auto file = (missingParent / "state.json").string();
  fs::remove_all(base);

  {
    iora::storage::JsonFileStore store(file); // parent missing -> starts empty, no throw
    store.set("k", std::string("v"));
    store.flush();                            // open fails -> write fails -> _dirty retained
    REQUIRE_FALSE(fs::exists(file));          // nothing written yet

    fs::create_directories(missingParent);    // parent now exists
    store.flush();                            // retries ONLY because _dirty was retained
    REQUIRE(fs::exists(file));                // proves the failed flush did NOT clear _dirty

    std::ifstream in(file);
    const std::string content((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    REQUIRE(content.find("\"v\"") != std::string::npos);
  }
  fs::remove_all(base);
}

// Regression: the background flush thread must actually persist a dirty store to
// disk on its own (not just the destructor). Poll for the file WHILE the store
// is still alive, so the dtor's flush() cannot be what wrote it.
TEST_CASE("JsonFileStore background thread persists a dirty store to disk",
          "[state][JsonFileStore][concurrency]")
{
  const std::string f = "bg_persist.json";
  std::filesystem::remove(f);

  iora::storage::JsonFileStore::setFlushInterval(std::chrono::milliseconds(2));

  bool persisted = false;
  {
    iora::storage::JsonFileStore store(f);
    store.set("bgkey", std::string("bgval"));
    for (int i = 0; i < 500 && !persisted; ++i)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
      std::ifstream in(f);
      if (in)
      {
        const std::string content((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
        if (content.find("bgval") != std::string::npos)
        {
          persisted = true;
        }
      }
    }
    REQUIRE(persisted); // written by the BACKGROUND thread while the store is alive
  }

  iora::storage::JsonFileStore::setFlushInterval(std::chrono::milliseconds(2000));
  std::filesystem::remove(f);
}
