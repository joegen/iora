# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Iora** - A modern C++17 microservice framework with ZERO external dependencies (except OpenSSL for TLS). Production-ready with unified transport layer, plugin architecture, and built-in HTTP/JSON/XML parsers.

## Build Commands

### Quick Build
```bash
# From project root
cmake -S . -B build
cmake --build build

# Run all tests
make check
# or run individual tests
./build/tests/iora_test_<name>
```

### Install System-Wide
```bash
sudo cmake --install build
# Creates: /usr/local/bin/iora, /usr/local/include/iora/, /usr/local/lib/iora/modules/
```

### Build Plugins Only
```bash
cmake --build build --target microservice_plugin
cmake --build build --target mod_kvstore
cmake --build build --target mod_jsonrpc_server
cmake --build build --target mod_jsonrpc_client
```

## Testing Commands

### Run All Tests
```bash
make check  # Runs CTest with output on failure
```

### Run Individual Test Suites
```bash
./build/tests/iora_test_logger
./build/tests/iora_test_http
./build/tests/iora_test_json_parser
./build/tests/iora_test_xml_parser
./build/tests/iora_test_timer
./build/tests/iora_test_plugin
```

### Run Sample Plugin
```bash
export OPENAI_API_KEY="your-key"
./build/src/iora --config sample/config_with_plugin.toml
```

## Architecture & Key Patterns

### Header-Only Design
- Main entry: `include/iora/iora.hpp`
- All components in single include tree
- Plugin system via `IoraService::instance()`

### Plugin API Access Patterns
```cpp
// Thread-safe wrapper (recommended) - ~25ns overhead
auto api = service.getExportedApiSafe<ReturnType(Args...)>("plugin.method");

// Direct call - ~120ns overhead
service.callExportedApi<ReturnType, Args...>("plugin.method", args...);

// Unsafe direct reference (single-thread only) - ~2ns overhead
auto api = service.getExportedApi<ReturnType(Args...)>("plugin.method");
```

### Built-in Parsers (Zero Dependencies)
- **JSON**: Custom DOM parser in `parsers/json.hpp`
- **XML**: Strict XML 1.0 parser with Pull/SAX/DOM APIs in `parsers/xml.hpp`
- **TOML**: Minimal config parser (~650 lines) in `parsers/minimal_toml.hpp`

### Core Components
- `network::UnifiedSharedTransport` - TCP/UDP connection pooling
- `network::HttpClient` - HTTPS support with OpenSSL
- `network::WebhookServer` - Production webhook handler
- `core::TimerService` - Microsecond-precision timers
- `core::ThreadPool` - Work-stealing thread pool
- `storage::JsonFileStore` - Persistent KV store
- `util::ExpiringCache<K,V>` - TTL cache with LRU

## Code Standards

### Style (Applied Informatics C++ v1.5)
- 2-space indentation, no tabs
- Allman braces (except namespaces)
- `#pragma once` for headers
- `.hpp` extensions for all headers

### Naming
- `camelCase` - functions, variables
- `PascalCase` - classes, structs
- `_prefix` - private members
- `UPPER_CASE` - constants

### Safety Rules
- No raw `new`/`delete` - use smart pointers
- No global variables
- Always qualify `std::`
- RAII for all resources

## Plugin Development

### Creating a Plugin
```cpp
#include "iora/iora.hpp"

class MyPlugin : public iora::IoraService::Plugin {
public:
  explicit MyPlugin(iora::IoraService* service) : Plugin(service) {}
  
  void onLoad(iora::IoraService* service) override {
    // Export API methods
    service->exportApi("myplugin.process", 
      [](const std::string& input) { return processData(input); });
  }
  
  void onUnload() override {
    // Cleanup
  }
};

IORA_DECLARE_PLUGIN(MyPlugin);
```

### Available Production Plugins
- **mod_kvstore** - Binary KV store with WAL and compaction
- **mod_jsonrpc_server** - JSON-RPC 2.0 server
- **mod_jsonrpc_client** - JSON-RPC client with pooling

## Common Tasks

### Add New Test
1. Create `tests/iora_test_myfeature.cpp`
2. Add to `tests/CMakeLists.txt` INDIVIDUAL_TESTS list
3. Include test helpers: `#include "test_helpers.hpp"`
4. Run: `cmake --build build && ./build/tests/iora_test_myfeature`

### Debug Build
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

### Check Dependencies
```bash
# Only external dependency should be OpenSSL
ldd build/src/iora | grep -v "linux-vdso\|ld-linux\|libc\|libm\|libdl\|libpthread\|libgcc\|libstdc++"
```

## Important Notes

- **No External JSON/XML Libraries** - Use built-in parsers
- **Plugin System Required** - Never call `IoraService::init()` directly
- **Thread Safety** - Use `getExportedApiSafe()` for multi-threaded plugin calls
- **Test Before Commit** - Always run `make check`
- **Config Path** - Default: `/etc/iora.conf.d/iora.cfg`