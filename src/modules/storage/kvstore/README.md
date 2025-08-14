# KVStore Module

## Overview
The KVStore module provides a persistent, thread-safe key/value store for binary and string data, designed to be loaded as a plugin in the Iora microservice framework. It supports atomic batch operations, in-memory caching, and optional background compaction. All APIs use only public, portable types for maximum compatibility.

## API Summary

| API Name           | Signature (callExportedApi)                                                                 | Description                                 |
|--------------------|---------------------------------------------------------------------------------------------|---------------------------------------------|
| kvstore.get        | std::optional<std::vector<uint8_t>> (const std::string& key)                                | Get binary value for a key                  |
| kvstore.set        | void (const std::string& key, const std::vector<uint8_t>& value)                            | Set binary value for a key                  |
| kvstore.setBatch   | void (const std::unordered_map<std::string, std::vector<uint8_t>>& batch)                   | Set multiple key/value pairs atomically     |
| kvstore.getBatch   | std::unordered_map<std::string, std::vector<uint8_t>> (const std::vector<std::string>& keys)| Get multiple values; missing keys omitted   |
| kvstore.getString  | std::optional<std::string> (const std::string& key)                                         | Get string value for a key                  |
| kvstore.setString  | void (const std::string& key, const std::string& value)                                     | Set string value for a key                  |

## Usage Examples

```cpp
// Load the plugin
iora::IoraService& svc = iora::IoraService::instance();
std::string pluginPath = "/path/to/mod_kvstore.so";
assert(svc.loadSingleModule(pluginPath));

// Set and get binary value
std::vector<uint8_t> value = {1,2,3};
svc.callExportedApi<void, const std::string&, const std::vector<uint8_t>&>("kvstore.set", "mykey", value);
auto opt = svc.callExportedApi<std::optional<std::vector<uint8_t>>, const std::string&>("kvstore.get", "mykey");
if (opt) std::cout << "Value size: " << opt->size() << std::endl;

// Set and get string value
svc.callExportedApi<void, const std::string&, const std::string&>("kvstore.setString", "name", "iora");
auto sopt = svc.callExportedApi<std::optional<std::string>, const std::string&>("kvstore.getString", "name");
if (sopt) std::cout << "name=" << *sopt << std::endl;

// Batch set/get
std::unordered_map<std::string, std::vector<uint8_t>> batch = {{"a", {1,2}}, {"b", {3,4}}};
svc.callExportedApi<void, const std::unordered_map<std::string, std::vector<uint8_t>>&>("kvstore.setBatch", batch);
auto results = svc.callExportedApi<std::unordered_map<std::string, std::vector<uint8_t>>, const std::vector<std::string>&>("kvstore.getBatch", std::vector<std::string>{"a","b"});
```

## Configuration Options

All options are read from the config loader under `iora.modules.kvstore`:

| Key                        | Type      | Default         | Description                       |
|----------------------------|-----------|-----------------|-----------------------------------|
| path                       | string    | "kvstore.bin"  | Path to store file                |
| max_log_size               | int       | (module default)| Max log size in bytes             |
| max_cache_size             | int       | (module default)| Max cache entries                 |
| background_compaction      | bool      | false           | Enable background compaction      |
| compaction_interval_ms     | int       | (module default)| Compaction interval (ms)          |

Example TOML:
```toml
[iora.modules.kvstore]
path = "kvstore.bin"
max_log_size = 10485760
max_cache_size = 1000
background_compaction = true
compaction_interval_ms = 60000
```

## Error Handling Guidance
- All get APIs return `std::optional` (absence = key not found).
- Set and batch APIs are `void`; errors during initialization or I/O throw `std::runtime_error`.
- Always check for plugin load success and handle exceptions at the service/plugin level.

## Integration and Testing Instructions
- Place all tests in `src/modules/storage/kvstore/tests/`.
- Use a helper to create a test service with `autoLoad = false` and deterministic config:
  ```cpp
  iora::IoraService& createTestService()
  {
    static bool initialized = false;
    if (!initialized)
    {
      iora::IoraService::Config cfg;
      cfg.server.port = 8135;
      cfg.log.file = "kvstore_test";
      cfg.log.level = "info";
      cfg.modules.autoLoad = false;
      try { iora::IoraService::shutdown(); } catch(...) {}
      iora::IoraService::init(cfg);
      initialized = true;
    }
    return iora::IoraService::instance();
  }
  ```
- In your test `main`, resolve plugin paths and load them explicitly. Assert plugin existence and loading before running tests.
- Use `callExportedApi` to exercise all APIs and validate results.
- Clean up state by calling `IoraService::shutdown()` or using `IoraService::AutoServiceShutdown`.

## License
This module is part of Iora and is licensed under the Mozilla Public License 2.0. See the top-level LICENSE file for details.
