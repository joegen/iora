#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include <chrono>
#include <iomanip>
#include "test_helpers.hpp"

using namespace iora::test;

TEST_CASE("Dynamic loading of testplugin shared library")
{
  initializeTestLogging();

  // Setup IoraService config
  iora::IoraService::Config config;
  config.server.port = 8130;
  config.state.file = "ioraservice_plugin_state.json";
  config.log.file = "ioraservice_plugin_log";

  // Initialize service with config
  iora::IoraService::init(config);
  iora::IoraService& svc = iora::IoraService::instance();
  AutoServiceShutdown autoShutdown(svc);

  auto pluginPathOpt = iora::util::getExecutableDir() + "/plugins/testplugin.so";
  std::cout << "Plugin path: " << pluginPathOpt << std::endl;
  REQUIRE(std::filesystem::exists(pluginPathOpt));
  REQUIRE(svc.loadSingleModule(pluginPathOpt));

  SECTION("callExportedApi: add")
  {
    int sum = svc.callExportedApi<int, int, int>("testplugin.add", 2, 3);
    REQUIRE(sum == 5);
  }

  SECTION("callExportedApi: greet")
  {
    std::string greet = svc.callExportedApi<std::string, const std::string&>("testplugin.greet", "World");
    REQUIRE(greet == "Hello, World!");
  }

  SECTION("callExportedApi: toggleLoaded and isLoaded")
  {
    bool loaded1 = svc.callExportedApi<bool>("testplugin.isLoaded");
    bool toggled = svc.callExportedApi<bool>("testplugin.toggleLoaded");
    bool loaded2 = svc.callExportedApi<bool>("testplugin.isLoaded");
    REQUIRE(loaded1 == true);
    REQUIRE(toggled == false);
    REQUIRE(loaded2 == false);
  }

  SECTION("getExportedApi: add")
  {
    auto addApi = svc.getExportedApi<int(int, int)>("testplugin.add");
    REQUIRE(addApi(10, 20) == 30);
  }

  SECTION("getExportedApi: greet")
  {
    auto greetApi = svc.getExportedApi<std::string(const std::string&)>("testplugin.greet");
    REQUIRE(greetApi("Iora") == "Hello, Iora!");
  }

  SECTION("getExportedApiSafe: basic functionality")
  {
    auto safeAddApi = svc.getExportedApiSafe<int(int, int)>("testplugin.add");
    REQUIRE(safeAddApi(5, 7) == 12);
    REQUIRE(safeAddApi.isAvailable() == true);
    REQUIRE(safeAddApi.getModuleName() == "testplugin.so");  // Should be full filename
    REQUIRE(safeAddApi.getApiName() == "testplugin.add");

    auto safeGreetApi = svc.getExportedApiSafe<std::string(const std::string&)>("testplugin.greet");
    REQUIRE(safeGreetApi("SafeAPI") == "Hello, SafeAPI!");
    REQUIRE(safeGreetApi.isAvailable() == true);
  }

  SECTION("getExportedApiSafe: handles module unloading gracefully")
  {
    // Create safe API wrappers before unloading
    auto safeAddApi = svc.getExportedApiSafe<int(int, int)>("testplugin.add");
    auto safeGreetApi = svc.getExportedApiSafe<std::string(const std::string&)>("testplugin.greet");

    // Test that they work initially
    REQUIRE(safeAddApi(3, 4) == 7);
    REQUIRE(safeGreetApi("Test") == "Hello, Test!");
    REQUIRE(safeAddApi.isAvailable() == true);

    // Unload the module
    REQUIRE(svc.unloadSingleModule("testplugin.so"));

    // Wait a bit for event processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Safe API should now report module as unavailable
    REQUIRE(safeAddApi.isAvailable() == false);
    REQUIRE(safeGreetApi.isAvailable() == false);

    // Calling the safe APIs should throw proper exceptions instead of crashing
    bool addThrew = false;
    bool greetThrew = false;
    std::string addError, greetError;

    try
    {
      safeAddApi(1, 1);
    }
    catch (const std::runtime_error& e)
    {
      addThrew = true;
      addError = e.what();
    }

    try
    {
      safeGreetApi("Test");
    }
    catch (const std::runtime_error& e)
    {
      greetThrew = true;
      greetError = e.what();
    }

    REQUIRE(addThrew);
    REQUIRE(greetThrew);
    REQUIRE(addError.find("module 'testplugin.so' not loaded") != std::string::npos);
    REQUIRE(greetError.find("module 'testplugin.so' not loaded") != std::string::npos);

    // Reload the module and verify safe APIs work again
    REQUIRE(svc.loadSingleModule(pluginPathOpt));

    // Wait a bit for event processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    REQUIRE(safeAddApi.isAvailable() == true);
    REQUIRE(safeGreetApi.isAvailable() == true);
    REQUIRE(safeAddApi(10, 15) == 25);
    REQUIRE(safeGreetApi("Reloaded") == "Hello, Reloaded!");
  }

  SECTION("Plugin reload: unload and reload shared library")
  {
    REQUIRE(svc.unloadSingleModule("testplugin.so"));

    bool threw = false;
    try
    {
      (void)svc.callExportedApi<int, int, int>("testplugin.add", 1, 1);
    }
    catch (...)
    {
      threw = true;
    }
    REQUIRE(threw);

    REQUIRE(svc.loadSingleModule(pluginPathOpt));
    REQUIRE(svc.callExportedApi<int, int, int>("testplugin.add", 7, 8) == 15);
    REQUIRE(svc.callExportedApi<std::string, const std::string&>("testplugin.greet", "Reloaded") == "Hello, Reloaded!");
  }

  SECTION("Comparison: unsafe vs safe API behavior on module unload")
  {
    // Get both unsafe and safe API references
    auto unsafeAdd = svc.getExportedApi<int(int, int)>("testplugin.add");
    auto safeAdd = svc.getExportedApiSafe<int(int, int)>("testplugin.add");

    // Both should work initially
    REQUIRE(unsafeAdd(1, 2) == 3);
    REQUIRE(safeAdd(1, 2) == 3);

    // Unload module
    REQUIRE(svc.unloadSingleModule("testplugin.so"));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Safe API should throw a clear exception
    bool safeThrew = false;
    try
    {
      safeAdd(1, 2);
    }
    catch (const std::runtime_error& e)
    {
      safeThrew = true;
      std::string error = e.what();
      REQUIRE(error.find("module 'testplugin.so' not loaded") != std::string::npos);
    }
    REQUIRE(safeThrew);

    // NOTE: We don't test the unsafe API calling after unload because it would
    // likely cause a segmentation fault and crash the test. This demonstrates
    // why the safe API is necessary.

    // Reload and verify safe API works again
    REQUIRE(svc.loadSingleModule(pluginPathOpt));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    REQUIRE(safeAdd(5, 6) == 11);
  }

  SECTION("Thread safety test: concurrent API calls during module unload/reload")
  {
    // This test verifies that SafeApiFunction is thread-safe:
    // - Multiple threads can call the API concurrently
    // - Module unload/reload events are handled safely
    // - No race conditions or crashes occur
    // - Proper exceptions are thrown when module is unavailable
    auto safeAddApi = svc.getExportedApiSafe<int(int, int)>("testplugin.add");

    const int numThreads = 10;
    const int callsPerThread = 100;
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    std::atomic<int> exceptionCount{0};
    std::atomic<bool> stopTest{false};

    // Start worker threads that continuously call the API
    for (int i = 0; i < numThreads; ++i)
    {
      threads.emplace_back(
          [&, i]()
          {
            for (int j = 0; j < callsPerThread && !stopTest.load(); ++j)
            {
              try
              {
                int result = safeAddApi(i, j);
                if (result == i + j)
                {
                  successCount.fetch_add(1);
                }
                std::this_thread::sleep_for(std::chrono::microseconds(10));
              }
              catch (const std::runtime_error& e)
              {
                exceptionCount.fetch_add(1);
                // Expected when module is unloaded
              }
              catch (...)
              {
                // Unexpected exception - this would indicate a race condition
                std::cout << "UNEXPECTED EXCEPTION in thread " << i << std::endl;
                stopTest.store(true);
              }
            }
          });
    }

    // Let threads run for a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Unload and reload module multiple times while threads are running
    for (int cycle = 0; cycle < 5; ++cycle)
    {
      REQUIRE(svc.unloadSingleModule("testplugin.so"));
      std::this_thread::sleep_for(std::chrono::milliseconds(5));

      REQUIRE(svc.loadSingleModule(pluginPathOpt));
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Let threads continue for a bit more
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    stopTest.store(true);

    // Wait for all threads to finish
    for (auto& t : threads)
    {
      t.join();
    }

    std::cout << "Thread safety test completed:" << std::endl;
    std::cout << "  Success count: " << successCount.load() << std::endl;
    std::cout << "  Exception count: " << exceptionCount.load() << std::endl;
    std::cout << "  Total calls: " << successCount.load() + exceptionCount.load() << std::endl;

    // Test should complete without crashes or unexpected exceptions
    REQUIRE((successCount.load() + exceptionCount.load()) > 0);

    // Verify thread safety: total calls should equal expected maximum
    int expectedMaxCalls = numThreads * callsPerThread;
    int actualCalls = successCount.load() + exceptionCount.load();
    REQUIRE(actualCalls <= expectedMaxCalls);  // Some threads may exit early due to stopTest
  }

  SECTION("Performance benchmark: Safe vs Unsafe vs CallExportedApi")
  {
    auto unsafeAddApi = svc.getExportedApi<int(int, int)>("testplugin.add");
    auto safeAddApi = svc.getExportedApiSafe<int(int, int)>("testplugin.add");

    const int numCalls = 100000;  // 100k calls for statistically significant results

    // Warm up all APIs to ensure caches are populated
    unsafeAddApi(1, 1);
    safeAddApi(1, 1);
    svc.callExportedApi<int, int, int>("testplugin.add", 1, 1);

    // Benchmark 1: Unsafe API (raw std::function)
    auto unsafeStart = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < numCalls; ++i)
    {
      volatile int result = unsafeAddApi(i % 100, (i + 1) % 100);
      (void)result;  // Prevent optimization
    }
    auto unsafeEnd = std::chrono::high_resolution_clock::now();
    auto unsafeDuration = std::chrono::duration_cast<std::chrono::nanoseconds>(unsafeEnd - unsafeStart);

    // Benchmark 2: Safe API (cached path - module stays loaded)
    auto safeStart = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < numCalls; ++i)
    {
      volatile int result = safeAddApi(i % 100, (i + 1) % 100);
      (void)result;  // Prevent optimization
    }
    auto safeEnd = std::chrono::high_resolution_clock::now();
    auto safeDuration = std::chrono::duration_cast<std::chrono::nanoseconds>(safeEnd - safeStart);

    // Benchmark 3: callExportedApi (lookups every call)
    auto callStart = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < numCalls; ++i)
    {
      volatile int result = svc.callExportedApi<int, int, int>("testplugin.add", i % 100, (i + 1) % 100);
      (void)result;  // Prevent optimization
    }
    auto callEnd = std::chrono::high_resolution_clock::now();
    auto callDuration = std::chrono::duration_cast<std::chrono::nanoseconds>(callEnd - callStart);

    // Calculate metrics
    double unsafeNsPerCall = static_cast<double>(unsafeDuration.count()) / numCalls;
    double safeNsPerCall = static_cast<double>(safeDuration.count()) / numCalls;
    double callNsPerCall = static_cast<double>(callDuration.count()) / numCalls;

    double safeOverheadNs = safeNsPerCall - unsafeNsPerCall;
    double safeOverheadPercent = (safeOverheadNs / unsafeNsPerCall) * 100.0;

    std::cout << "\n=== Performance Benchmark Results ===" << std::endl;
    std::cout << "Test: " << numCalls << " API calls each" << std::endl;
    std::cout << "1. Unsafe API (getExportedApi):     " << std::fixed << std::setprecision(2) << unsafeNsPerCall
              << " ns/call" << std::endl;
    std::cout << "2. Safe API (getExportedApiSafe):   " << std::fixed << std::setprecision(2) << safeNsPerCall
              << " ns/call" << std::endl;
    std::cout << "3. CallExportedApi (lookup each):   " << std::fixed << std::setprecision(2) << callNsPerCall
              << " ns/call" << std::endl;
    std::cout << "\nSafe API overhead: " << std::fixed << std::setprecision(2) << safeOverheadNs << " ns/call ("
              << std::fixed << std::setprecision(1) << safeOverheadPercent << "%)" << std::endl;

    // Safe API should be faster than callExportedApi (which does lookup each time)
    REQUIRE(safeNsPerCall < callNsPerCall);

    // Performance should be reasonable - safe API overhead should be under 50ns per call
    // The percentage can be high if the base unsafe call is very fast (few nanoseconds)
    REQUIRE(safeOverheadNs < 50.0);  // Less than 50ns absolute overhead per call
  }

  SECTION("Performance: Safe API cache invalidation cost")
  {
    auto safeAddApi = svc.getExportedApiSafe<int(int, int)>("testplugin.add");

    // Warm up
    safeAddApi(1, 1);

    // Measure cache refresh cost (first call after invalidation)
    std::vector<double> refreshTimes;

    for (int i = 0; i < 10; ++i)
    {
      // Force cache invalidation by simulating module reload
      svc.unloadSingleModule("testplugin.so");
      svc.loadSingleModule(pluginPathOpt);
      std::this_thread::sleep_for(std::chrono::milliseconds(1));  // Let events process

      // Measure first call after reload (cache miss)
      auto start = std::chrono::high_resolution_clock::now();
      volatile int result = safeAddApi(i, i + 1);
      auto end = std::chrono::high_resolution_clock::now();
      (void)result;

      double refreshNs = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
      refreshTimes.push_back(refreshNs);
    }

    // Calculate average refresh time
    double avgRefreshNs = 0;
    for (double time : refreshTimes)
    {
      avgRefreshNs += time;
    }
    avgRefreshNs /= refreshTimes.size();

    std::cout << "\n=== Cache Refresh Performance ===" << std::endl;
    std::cout << "Average cache refresh time: " << std::fixed << std::setprecision(0) << avgRefreshNs << " ns"
              << std::endl;
    std::cout << "This cost is only paid on first call after module reload" << std::endl;

    // Cache refresh should complete within reasonable time (typically < 10μs)
    REQUIRE(avgRefreshNs < 50000.0);  // Less than 50μs for cache refresh
  }

  iora::util::removeFilesContainingAny({"ioraservice_plugin_log", "ioraservice_plugin_state.json"});
}
