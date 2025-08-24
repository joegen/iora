# Iora

**Iora** is a modern **C++17 application framework for high-performance networked applications** with **ZERO external dependencies** (except OpenSSL for TLS). Designed for production environments, it provides a unified transport layer, advanced networking capabilities, dynamic plugin system, and comprehensive tooling — making it ideal for distributed systems, API gateways, real-time applications, and beyond.

---

## 🐦 What's In The Name?

**Iora** is named after the *Common Iora*, a small but remarkably agile songbird native to Southeast Asia. Known for its vibrant presence and melodic call, the iora thrives in diverse environments — from dense forests to open gardens.

The same philosophy inspired this framework:
- 🌱 **Lightweight** yet powerful — minimal overhead, maximum capability
- 🧩 **Modular** architecture — compose exactly what you need  
- ⚡ **High-performance** by design — unified transport layer with connection pooling
- 🌍 **Adaptable** — from embedded systems to distributed cloud services

The name is also a **recursive acronym**:

> **Iora Orchestrates Routing Asynchronously**

Like the bird it's named after, `iora` thrives in diverse environments — whether you're building microservices, API gateways, IoT backends, real-time systems, or distributed applications. It's small enough to embed anywhere, yet powerful enough for production at scale.

---

## 🎯 Why Choose Iora?

- **🚀 Production Ready** — Battle-tested components with comprehensive error handling and graceful degradation
- **⚡ High Performance** — Unified transport layer with connection pooling, batching, and circuit breakers
- **🛠️ Developer Friendly** — Header-only library with intuitive APIs and extensive documentation
- **🔧 Extensible** — Dynamic plugin system for custom functionality without recompilation
- **🏗️ Modern C++** — Clean C++17 design with RAII, smart pointers, and zero-cost abstractions
- **🎯 ZERO External Dependencies** — Completely self-contained! Only requires OpenSSL for TLS support

### Perfect For
- **API Gateways** — Route and transform requests with built-in load balancing
- **Real-time Systems** — Event-driven architecture with sub-millisecond response times  
- **Distributed Services** — Microservices, serverless functions, and cloud-native applications
- **IoT Backends** — Handle thousands of concurrent device connections efficiently
- **Webhook Processors** — Reliable webhook handling with retry logic and dead letter queues

---

## 🎯 Zero External Dependencies

Iora is **completely self-contained** with all functionality built-in:

### Built-in Components (No External Libraries!)
- **HTTP Client & Server** — Custom implementation with full TLS support
- **JSON Parser** — 🚀 **Ultra-fast custom JSON implementation** with DOM API compatibility
- **XML Parser** — 🔧 **Strict XML 1.0 parser** with pull, SAX, and DOM APIs
- **TOML Parser** — Minimal, efficient configuration parser (~650 lines)
- **Thread Pool** — Custom work-stealing implementation
- **Logging System** — Async logging with rotation
- **Shell Execution** — Secure command runner
- **Event System** — Built-in pub/sub and event queue

### The Only Exception: OpenSSL
- Required **only** for TLS/HTTPS support
- Can be disabled if TLS is not needed
- Standard system library on most platforms

### Benefits
- **Fast Compilation** — No dependency downloads or builds
- **Easy Integration** — Just include and compile
- **Predictable Behavior** — No version conflicts
- **Small Binary Size** — No bloated dependencies
- **Full Control** — All code is visible and modifiable

---

## ✨ Core Features

### 🌐 Network & Transport
- **UnifiedSharedTransport** — High-performance transport layer with TCP/UDP support
- **network::HttpClient** — Advanced HTTP client with connection pooling and retry logic
- **network::WebhookServer** — Production-grade webhook server with TLS and authentication
- **network::CircuitBreaker** — Prevent cascade failures with configurable circuit breaking
- **network::ConnectionHealth** — Real-time connection monitoring and automatic recovery

### 💾 Storage & State Management  
- **storage::JsonFileStore** — JSON-backed persistent key-value store with background flushing
- **storage::ConcreteStateStore** — Thread-safe in-memory key-value store with case-insensitive keys
- **util::ExpiringCache<K,V>** — Thread-safe TTL cache with LRU eviction policies

### 🛠️ Development & Operations
- **core::ThreadPool** — Dynamic, exception-safe thread pool with work stealing
- **core::TimerService** — High-performance timer system with microsecond precision
- **core::Logger** — Structured logging with async I/O and log rotation
- **core::ConfigLoader** — Hot-reloadable TOML configuration with built-in parser (see [docs](docs/minimal_toml_parser.md))
- **system::ShellRunner** — Secure shell command execution with timeout and sandboxing
- **core::EventQueue** — High-throughput event processing with backpressure handling

### 🔌 Extensions & Modules
- **iora::IoraService** — Plugin orchestration system with hot-loading support
- **Dynamic Plugin Loading** — Runtime module loading without recompilation
- **Extensible API System** — Clean interfaces for cross-plugin communication

---

## 🚀 High-Performance JSON Parser

Iora features a **custom-built JSON parser** designed for maximum performance and minimal dependencies. Unlike heavy external libraries, our parser is:

### ⚡ **Lightning Fast**
- **Single-header implementation** — No external dependencies
- **DOM-style API** — Familiar interface compatible with popular JSON libraries
- **Optimized for microservice payloads** — Perfect for API gateways and web services
- **Memory efficient** — Smart use of `std::variant` and small-vector optimization

### 🎯 **Feature Complete**
- **Full JSON support** — Objects, arrays, strings, numbers, booleans, null
- **Pretty printing** — Configurable formatting with indentation and key sorting
- **Error reporting** — Detailed parse errors with line and column information  
- **Stream parsing** — Handle large JSON documents incrementally
- **Safe parsing** — Built-in limits to prevent resource exhaustion

### 🔧 **Developer Friendly**
- **Familiar API** — Drop-in replacement syntax for common JSON operations
- **Type safety** — Template-based getters with compile-time type checking
- **Exception handling** — Both throwing and non-throwing parse variants
- **Range-based loops** — Iterate over arrays and objects naturally

### 📝 **Usage Example**

```cpp
#include "iora/iora.hpp"

// Parse JSON from string
auto json = iora::parsers::Json::parseOrThrow(R"({
  "users": [
    {"name": "Alice", "age": 30},
    {"name": "Bob", "age": 25}
  ],
  "total": 2
})");

// Access data with familiar syntax
std::cout << "Total users: " << json["total"].get<int>() << std::endl;

// Iterate over arrays
for (const auto& user : json["users"].getArray()) {
  std::cout << user["name"].get<std::string>() 
            << " is " << user["age"].get<int>() 
            << " years old" << std::endl;
}

// Create JSON programmatically
auto response = iora::parsers::Json::object();
response["status"] = "success";
response["data"] = iora::parsers::Json::array();
response["data"].push_back("item1");
response["data"].push_back("item2");

// Serialize with pretty printing
std::cout << response.dump(2) << std::endl;
```

### 🏆 **Why Custom?**
- **Zero dependencies** — No external JSON library bloat
- **Optimized for Iora** — Designed specifically for high-performance networking
- **Full control** — We can optimize, debug, and extend as needed
- **Predictable performance** — No surprise allocations or hidden complexity
- **Small binary size** — Contributes to Iora's minimal footprint

---

## 🔧 Production-Ready XML Parser

Iora includes a **strict, secure XML 1.0 parser** with multiple API styles to suit different use cases. Built for production environments where security and correctness matter:

### 🛡️ **Security First**
- **No external entity expansion** — Prevents XXE attacks by design
- **Configurable limits** — Depth, attributes, name length, and token limits
- **Well-formedness validation** — Strict tag balance checking and error reporting
- **Memory safe** — No buffer overflows or resource exhaustion attacks

### 🎯 **Three API Styles**
- **Pull Parser** — Stream-based token-by-token parsing for maximum control
- **SAX Callbacks** — Event-driven parsing with minimal memory footprint
- **DOM Builder** — Optional in-memory tree for convenient navigation

### ⚡ **Performance & Features**
- **Header-only** — Zero external dependencies, just include and use
- **UTF-8 native** — Full Unicode support with entity decoding
- **Namespace aware** — Prefix/localName splitting for XML namespaces
- **CDATA & Comments** — Full support for all XML constructs
- **Detailed errors** — Line/column error reporting for debugging

### 📝 **Usage Examples**

```cpp
#include "iora/iora.hpp"
using namespace iora::parsers::xml;

// Pull parsing for streaming
Parser parser("<root><item id='1'>Hello</item></root>");
while (parser.next()) {
  const auto& token = parser.current();
  if (token.kind == TokenKind::StartElement) {
    std::cout << "Element: " << token.name << std::endl;
    for (const auto& attr : token.attributes) {
      std::cout << "  @" << attr.name << " = " << attr.value << std::endl;
    }
  }
}

// SAX-style callbacks for event processing
SaxCallbacks callbacks;
callbacks.onStartElement = [](const Token& t) {
  std::cout << "Start: " << t.name << std::endl;
};
callbacks.onText = [](const Token& t) {
  std::string decoded;
  Parser::decodeEntities(t.text, decoded);
  std::cout << "Text: " << decoded << std::endl;
};
runSax(parser, callbacks);

// DOM for convenient navigation
auto document = DomBuilder::build(parser);
const Node* root = document->children[0].get();
const Node* item = root->childByName("item");
std::cout << "Item ID: " << item->getAttribute("id") << std::endl;
```

### 🏆 **Why Our Parser?**
- **Strict validation** — Catches malformed XML that permissive parsers miss
- **Production tested** — 260+ test assertions covering edge cases
- **Secure by default** — Built-in protection against common XML attacks
- **Zero dependencies** — No external XML library bloat
- **Optimized for services** — Perfect for SOAP, RSS, configuration files

---

## ⏱️ High-Performance Timer System

Iora includes a **sophisticated timer service** designed for high-throughput microservices that need precise timing and scheduling capabilities:

### ⚡ **Core Features**
- **High-resolution timers** — Microsecond precision with steady clock guarantees
- **Scalable architecture** — Single-threaded event loop per service, pool support for load distribution
- **Perfect forwarding** — Zero-copy handler support for move-only types
- **Periodic timers** — Repeating timers with automatic rescheduling
- **Cancellation support** — Cancel any timer before execution
- **Thread-safe** — All operations are thread-safe by design

### 🎯 **Advanced Capabilities**
- **TimerServicePool** — Distribute timers across multiple threads for massive scale
- **Statistics tracking** — Monitor timer performance and execution metrics
- **Error handling** — Configurable error handlers with exception safety
- **ASIO compatibility** — Drop-in replacement for boost::asio timers
- **Memory efficient** — Object pooling and smart pointer management

### 📊 **Performance Characteristics**
- **Millions of timers** — Handle millions of concurrent timers efficiently
- **Low latency** — Sub-millisecond scheduling overhead
- **Predictable behavior** — No allocation in hot paths
- **Work stealing** — Automatic load balancing in pool mode

### 🔧 **Usage Examples**

```cpp
#include "iora/iora.hpp"
using namespace iora::core;

// Create a timer service with custom configuration
auto config = TimerConfigBuilder()
    .enableStatistics(true)
    .maxConcurrentTimers(10000)
    .threadName("MyTimers")
    .build();

TimerService service(config);

// Schedule a one-shot timer
service.scheduleAfter(std::chrono::seconds(5), []() {
    std::cout << "Timer fired after 5 seconds!" << std::endl;
});

// Schedule a periodic timer
auto periodicId = service.schedulePeriodic(std::chrono::seconds(1), []() {
    std::cout << "Tick every second" << std::endl;
});

// Cancel a timer
service.cancel(periodicId);

// Use move-only handlers
auto resource = std::make_unique<MyResource>();
service.scheduleAfter(100ms, [r = std::move(resource)]() {
    r->process(); // Resource moved into timer
});

// Pool for high-throughput scenarios
TimerServicePool pool(4, config); // 4 timer threads
for (int i = 0; i < 100000; ++i) {
    pool.getService().scheduleAfter(1s, [i]() {
        processTask(i);
    });
}

// ASIO-compatible interface
SteadyTimer timer(service);
timer.expiresAfter(std::chrono::seconds(2));
timer.asyncWait([](bool canceled) {
    if (!canceled) {
        std::cout << "ASIO-style timer fired!" << std::endl;
    }
});

// Monitor performance
const auto& stats = service.getStats();
std::cout << "Timers scheduled: " << stats.timersScheduled << std::endl;
std::cout << "Timers executed: " << stats.timersExecuted << std::endl;
std::cout << "Average latency: " << stats.avgSchedulingLatency << "μs" << std::endl;
```

### 🏗️ **Architecture Benefits**
- **No external dependencies** — Pure C++17 implementation
- **Header-only option** — Can be used standalone
- **Tested at scale** — Battle-tested with millions of timers
- **Production ready** — Used in high-frequency trading systems
- **Graceful shutdown** — Proper cleanup of all pending timers

---

## 🔌 Available Plugins

Iora ships with three production-ready plugins, with more planned:

### 🗄️ **KVStore Plugin** (`mod_kvstore`)
High-performance binary key-value storage with advanced features:
- **Binary-optimized storage** with WAL (Write-Ahead Logging)
- **Background compaction** for optimal performance  
- **Configurable caching** with LRU eviction
- **Atomic operations** and crash recovery
- **Batch operations** for high-throughput scenarios

**API Methods:**
- `kvstore.get(key)` → `std::optional<std::vector<uint8_t>>`
- `kvstore.set(key, value)` → `void`
- `kvstore.setBatch(batch)` → `void` 
- `kvstore.getBatch(keys)` → `std::vector<std::optional<std::vector<uint8_t>>>`

### 🌐 **JSON-RPC Server Plugin** (`mod_jsonrpc_server`)
Full JSON-RPC 2.0 specification compliance with enterprise features:
- **Batch request processing** for improved efficiency
- **Method registration** with custom handlers
- **Authentication support** with configurable security
- **Real-time statistics** and monitoring
- **Request timeout handling** and circuit breaking

**API Methods:**
- `jsonrpc.register(methodName, handler)` → Register RPC methods
- `jsonrpc.getStats()` → Performance metrics and usage statistics
- `jsonrpc.registerWithOptions(method, handler, options)` → Advanced registration

### 📡 **JSON-RPC Client Plugin** (`mod_jsonrpc_client`)
Robust client for consuming JSON-RPC services:
- **Synchronous and asynchronous calls** for different use cases
- **Batch request support** for optimized network usage
- **Connection pooling** and automatic retry logic
- **Custom headers** and authentication support
- **Job tracking** for long-running async operations

**API Methods:**
- `jsonrpc.client.call(endpoint, method, params)` → Synchronous RPC calls
- `jsonrpc.client.callAsync(endpoint, method, params)` → Async with job tracking
- `jsonrpc.client.callBatch(endpoint, items)` → Batch processing
- `jsonrpc.client.notify(endpoint, method, params)` → Fire-and-forget notifications

### 🚀 **Sample Microservice Plugin**
Complete example demonstrating real-world usage:
- **Text summarization service** using OpenAI API
- **Asynchronous request processing** with status tracking
- **Webhook integration** for result notifications
- **State management** with persistent storage
- **Error handling** and graceful degradation

### 🔮 **Planned Plugins**
- **Authentication & Authorization** — OAuth2, JWT, and API key management
- **Message Queue** — Redis-compatible pub/sub and task queues  
- **Database Connectors** — PostgreSQL, MySQL, and MongoDB adapters
- **Monitoring & Metrics** — Prometheus, StatsD, and custom dashboards
- **Rate Limiting** — Token bucket and sliding window algorithms

---

## 🛠️ Build Instructions

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd iora
   ```

2. Configure the project:
   ```bash
   cmake -S . -B build
   ```

3. Build the project:
   ```bash
   cmake --build build
   ```

---

## 📦 Installation

After building, you can install Iora system-wide:

```bash
sudo cmake --install build
```

This installs:

- **Binary**: `iora` application → `/usr/local/bin/iora`
- **Headers**: Include files → `/usr/local/include/iora/`
- **Plugins**: Module libraries → `/usr/local/lib/iora/modules/`
- **Configuration**: Default config → `/etc/iora.conf.d/iora.cfg`

### Installation Paths

The configuration file defines several important paths where components store or locate files:

- **Log files**: `/var/log/iora/` (configurable via `iora.log.file`)
- **State storage**: `/etc/iora.conf.d/iora_state.json` (configurable via `iora.state.file`)
- **TLS certificates**: `/etc/iora.conf.d/tls/` (server.crt, server.key, ca.crt)
- **Module storage**: `/var/lib/iora/` (for plugin data like kvstore.bin)
- **Plugin directory**: `/usr/local/lib/iora/modules/` (configurable via `iora.modules.directory`)

After installation, you may need to create required directories and set appropriate permissions:

```bash
sudo mkdir -p /var/log/iora /var/lib/iora /etc/iora.conf.d/tls
sudo chown -R $(whoami) /var/log/iora /var/lib/iora
```

---

## ✅ Run Tests

1. Build the project (if not already built):
   ```bash
   cmake --build build
   ```

2. Run all tests:
   ```bash
   make check
   ```

---

## 🚀 Sample Microservice Plugin

A sample microservice plugin is available under `sample/plugins/`, demonstrating the **correct** way to use Iora:

- **HttpClient** for making HTTP requests  
- **WebhookServer** for receiving webhooks  
- **StateStore** for managing key-value state  
- **ExpiringCache** for TTL-based caching  
- **Logger** for structured logging
- **Plugin architecture** for modularity

### Build and Run

1. Build the sample plugin:
   ```bash
   cmake --build build --target microservice_plugin
   ```

2. Run the main Iora application with the plugin:
   ```bash
   export OPENAI_API_KEY="your-api-key"
   ./build/src/iora --config sample/config_with_plugin.toml
   ```

See `sample/plugins/README.md` for detailed usage instructions.

---

## 🔗 Linking to Iora

You can link to the Iora library using CMake, Autoconf, or a manual Makefile.

### CMake (Subdirectory)

```cmake
add_subdirectory(path/to/iora)
target_link_libraries(your_project PRIVATE iora_lib)
```

### CMake (FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(
    iora
    GIT_REPOSITORY <repository-url>
    GIT_TAG <commit-or-tag>
)
FetchContent_MakeAvailable(iora)
target_link_libraries(your_project PRIVATE iora_lib)
```

### Autoconf (`configure.ac`)

```m4
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
```

In your `Makefile.am`:

```makefile
your_project_CPPFLAGS = -Ipath/to/iora/include
your_project_LDADD = -lssl -lcrypto -lpthread
```

### Manual Makefile

```makefile
CXXFLAGS += -Ipath/to/iora/include -std=c++17
LDLIBS += -lssl -lcrypto -lpthread
```

Compile and link:

```bash
g++ -o your_project your_project.cpp $(CXXFLAGS) $(LDLIBS)
```

---

## 🔌 Plugin Support

Iora now supports a dynamic plugin system, allowing you to extend its functionality by loading plugins at runtime. Plugins are shared libraries that implement the `IoraService::Plugin` interface and are loaded using the `IORA_DECLARE_PLUGIN` macro.

### How It Works

1. **Plugin Interface**: All plugins must inherit from `IoraService::Plugin` and implement the `onLoad` and `onUnload` methods.
2. **Plugin Declaration**: Use the `IORA_DECLARE_PLUGIN` macro to define the `loadModule` function required for dynamic loading.
3. **Dynamic Loading**: Plugins are loaded from a specified directory at runtime. The directory can be configured via the `--modules` command-line argument or the configuration file.

### Example Plugin

Here is an example of a simple plugin:

```cpp
#include "iora/iora.hpp"

class MyPlugin : public iora::IoraService::Plugin
{
public:
  explicit MyPlugin(iora::IoraService* service) : Plugin(service) {}

  void onLoad(iora::IoraService* service) override
  {
    // Initialization logic
  }

  void onUnload() override
  {
    // Cleanup logic
  }
};

IORA_DECLARE_PLUGIN(MyPlugin);
```

### Configuration

To enable plugin loading, specify the directory containing your plugins:

- **Command-line**: Use the `--modules` argument:
  ```bash
  ./iora --modules /path/to/plugins
  ```

- **Configuration File**: Add the following to your TOML configuration:
  ```toml
  [modules]
  directory = "/path/to/plugins"
  ```

### Logging and Error Handling

- Plugin initialization errors are logged using the `iora::core::Logger`.
- If a plugin fails to load, it will be skipped, and the system will continue loading other plugins.

### JSON-RPC Server Module

The JSON-RPC Server module provides a JSON-RPC 2.0 compliant server that can be dynamically loaded as a plugin. It exposes the following API methods via `IoraService::exportApi`:

#### API Methods

- `jsonrpc.version()` → `std::uint32_t` - Returns the JSON-RPC server version
- `jsonrpc.register(methodName, handler)` → `void` - Registers a method handler
  - `methodName`: `const std::string&` - Name of the JSON-RPC method
  - `handler`: `std::function<iora::core::Json(const iora::core::Json&)>` - Handler function that takes JSON params and returns JSON result
- `jsonrpc.registerWithOptions(methodName, handler, options)` → `void` - Registers a method handler with options
  - `methodName`: `const std::string&` - Name of the JSON-RPC method  
  - `handler`: `std::function<iora::core::Json(const iora::core::Json&)>` - Handler function
  - `options`: `const iora::core::Json&` - Options object with optional fields:
    - `requireAuth`: `bool` - Whether authentication is required
    - `timeout`: `int` - Timeout in milliseconds  
    - `maxRequestSize`: `int` - Maximum request size in bytes
- `jsonrpc.unregister(methodName)` → `bool` - Unregisters a method
- `jsonrpc.has(methodName)` → `bool` - Checks if a method is registered
- `jsonrpc.getMethods()` → `std::vector<std::string>` - Returns list of registered method names
- `jsonrpc.getStats()` → `iora::core::Json` - Returns server statistics as JSON object with fields:
  - `totalRequests`: Total number of requests processed
  - `successfulRequests`: Number of successful requests
  - `failedRequests`: Number of failed requests
  - `timeoutRequests`: Number of timed out requests
  - `batchRequests`: Number of batch requests
  - `notificationRequests`: Number of notification requests
- `jsonrpc.resetStats()` → `void` - Resets all statistics counters

#### Usage Example

```cpp
// Load the JSON-RPC server module
auto& service = iora::IoraService::instance();
service.loadSingleModule("/path/to/mod_jsonrpc_server.so");

// Register a simple echo method
auto echoHandler = [](const iora::core::Json& params) -> iora::core::Json {
    return params; // Echo back the parameters
};
service.callExportedApi<void, const std::string&, std::function<iora::core::Json(const iora::core::Json&)>>(
    "jsonrpc.register", "echo", echoHandler);

// Register a method with options
auto authHandler = [](const iora::core::Json& params) -> iora::core::Json {
    return iora::core::Json{{"authenticated", true}};
};
iora::core::Json options;
options["requireAuth"] = true;
options["timeout"] = 5000;
service.callExportedApi<void, const std::string&, std::function<iora::core::Json(const iora::core::Json&)>, const iora::core::Json&>(
    "jsonrpc.registerWithOptions", "secure_method", authHandler, options);
```

## 🔒 Thread-Safe Plugin API Access

Iora provides three distinct methods for calling plugin APIs, each with different performance and safety characteristics:

### API Methods Overview

| Method | Performance | Thread Safety | Use Case |
|--------|-------------|---------------|----------|
| `getExportedApi` | **Fastest** (~2ns/call) | ⚠️ **Unsafe** | High-frequency calls, single-threaded |
| `getExportedApiSafe` | **Fast** (~25ns/call) | ✅ **Safe** | High-frequency calls, multi-threaded |
| `callExportedApi` | **Slower** (~120ns/call) | ✅ **Safe** | Occasional calls, any context |

### 1. `getExportedApi` - Maximum Performance (Unsafe)

**Performance**: ~2ns per call  
**Thread Safety**: ❌ **Not thread-safe** - can crash if module unloaded  
**Best for**: Single-threaded high-frequency API calls

```cpp
// Get direct function reference (fastest but unsafe)
auto addApi = service.getExportedApi<int(int, int)>("plugin.add");
int result = addApi(10, 20); // ~2ns overhead

// WARNING: If plugin is unloaded, this may crash with segmentation fault
```

### 2. `getExportedApiSafe` - High Performance + Safety

**Performance**: ~25ns per call (~25ns overhead for safety)  
**Thread Safety**: ✅ **Fully thread-safe** - throws exception if module unloaded  
**Best for**: Multi-threaded high-frequency API calls

```cpp
// Get thread-safe wrapper (recommended for most use cases)
auto safeAddApi = service.getExportedApiSafe<int(int, int)>("plugin.add");

// Safe to call from multiple threads concurrently
int result = safeAddApi(10, 20); // ~25ns overhead

// Check availability
if (safeAddApi.isAvailable()) {
    result = safeAddApi(5, 7);
}

// Get metadata
std::cout << "Module: " << safeAddApi.getModuleName() << std::endl;
std::cout << "API: " << safeAddApi.getApiName() << std::endl;

// Graceful error handling
try {
    result = safeAddApi(1, 2);
} catch (const std::runtime_error& e) {
    std::cout << "API unavailable: " << e.what() << std::endl;
}
```

### 3. `callExportedApi` - Direct Invocation

**Performance**: ~120ns per call (lookup overhead each time)  
**Thread Safety**: ✅ **Thread-safe** - validates module state on each call  
**Best for**: Occasional API calls, one-off invocations

```cpp
// Direct call with lookup each time (safest but slower)
try {
    int result = service.callExportedApi<int, int, int>("plugin.add", 10, 20);
    std::cout << "Result: " << result << std::endl;
} catch (const std::runtime_error& e) {
    std::cout << "Call failed: " << e.what() << std::endl;
}
```

### Performance Comparison

Based on benchmarking with 100,000 API calls:

```
=== Performance Benchmark Results ===
1. Unsafe API (getExportedApi):      2.10 ns/call   ⚡ Baseline
2. Safe API (getExportedApiSafe):   25.40 ns/call   🛡️ +23ns overhead (12x)
3. CallExportedApi (lookup each):  118.60 ns/call   🐌 +116ns overhead (56x)

Safe API overhead: 23.30 ns/call (1109.5% increase)
```

**Key Insights:**
- **Safe API** adds only **~23ns absolute overhead** for complete thread safety
- **Safe API** is **4-5x faster** than direct `callExportedApi`
- **Percentage overhead** is high because base unsafe call is extremely fast
- **Cache refresh cost** after module reload: ~50μs (one-time cost)

### Thread Safety Implementation

The `SafeApiFunction` class provides thread safety through:

#### Atomic State Management
```cpp
std::atomic<bool> valid{false};  // Lock-free availability check
```

#### Mutex-Protected Updates
```cpp
std::mutex cacheMutex;  // Protects cached function updates
```

#### Double-Checked Locking Pattern
```cpp
// Fast path - no lock needed if already cached and valid
if (valid.load(std::memory_order_acquire)) {
    return cachedFunc(std::forward<Args>(args)...);
}

// Slow path - acquire lock to refresh cache
std::lock_guard<std::mutex> lock(cacheMutex);
// ... refresh logic
```

#### Event-Driven Cache Invalidation
- Module unload events automatically invalidate all safe API wrappers
- Cache refresh is lazy - only happens on next API call
- No polling or background threads needed

### Migration Guide

#### From Unsafe to Safe API

```cpp
// Before (unsafe but fast)
auto api = service.getExportedApi<int(int, int)>("plugin.add");
int result = api(1, 2);

// After (safe with minimal overhead)
auto safeApi = service.getExportedApiSafe<int(int, int)>("plugin.add");
int result = safeApi(1, 2);
```

#### Error Handling Patterns

```cpp
// Pattern 1: Exception handling
try {
    auto result = safeApi(10, 20);
    processResult(result);
} catch (const std::runtime_error& e) {
    handleApiUnavailable(e.what());
}

// Pattern 2: Availability checking
if (safeApi.isAvailable()) {
    auto result = safeApi(10, 20);
    processResult(result);
} else {
    handleApiUnavailable("Module not loaded");
}
```

### Best Practices

#### Choose the Right Method
- **High-frequency + Single-threaded**: Use `getExportedApi` for maximum speed
- **High-frequency + Multi-threaded**: Use `getExportedApiSafe` for safety with minimal overhead
- **Occasional calls**: Use `callExportedApi` for simplicity

#### Performance Optimization
```cpp
// Cache safe API wrappers for reuse
class MyService {
    iora::IoraService::SafeApiFunction<int(int, int)> cachedAddApi;
    
public:
    MyService() : cachedAddApi(service.getExportedApiSafe<int(int, int)>("plugin.add")) {}
    
    int performCalculation(int a, int b) {
        return cachedAddApi(a, b); // ~25ns overhead
    }
};
```

#### Thread Safety Considerations
```cpp
// Safe: Multiple threads can call concurrently
std::vector<std::thread> workers;
for (int i = 0; i < 10; ++i) {
    workers.emplace_back([&safeApi, i]() {
        for (int j = 0; j < 1000; ++j) {
            try {
                int result = safeApi(i, j);
                processResult(result);
            } catch (const std::runtime_error&) {
                // Handle module unavailable
            }
        }
    });
}
```

### Real-World Performance Impact

For typical microservice workloads:

- **API Gateway**: 23ns overhead is negligible compared to network I/O (1-10ms)
- **High-Frequency Trading**: Unsafe API may be worth the risk for ultra-low latency
- **Multi-threaded Services**: Safe API prevents crashes, worth the small overhead
- **Plugin-Heavy Applications**: Safe API enables confident dynamic loading/unloading

The safe API overhead becomes insignificant when compared to typical business logic, database queries, or network operations, making it the recommended choice for most production scenarios.

---

## 📝 License

Iora is licensed under the [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/).  
You may use, modify, and redistribute the code under the terms of the MPL 2.0 license.

See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for more information and attributions for third-party dependencies.