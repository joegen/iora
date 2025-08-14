# Iora

**Iora** is a modern **C++17 header-only microservice foundation library** designed for lightweight, readable, and modular code. It provides components for HTTP services, webhook handling, shell execution, configuration, caching, and pluggable state storage — making it a solid base for event-driven, embedded, or general-purpose applications.

---

## 🐦 What's In The Name?

**Iora** is named after the *Common Iora*, a small but remarkably agile songbird native to Southeast Asia. Known for its vibrant presence and melodic call, the iora thrives in diverse environments — from dense forests to open gardens.

The same philosophy inspired this library:
- 🌱 **Lightweight** in footprint and dependencies  
- 🧩 **Modular** in structure  
- ⚡ **Responsive** by design — ideal for building asynchronous and event-driven systems

The name is also a **recursive acronym**:

> **Iora Orchestrates Routing Asynchronously**

While originally built to support projects in AI and VoIP, `iora` is designed to be **general-purpose** — useful for any C++17 application where modularity, clarity, and responsiveness matter. Like the bird it’s named after, `iora` is small, adaptable, and always ready to respond.

---

## ✨ Features

- **network::HttpClient** – Wraps `cpr` to call JSON REST APIs.
- **network::WebhookServer** – Wraps `cpp-httplib` to handle POST webhooks.
- **system::ShellRunner** – Executes Linux shell commands and captures stdout.
- **storage::JsonFileStore** – Abstract KV store with disk-backed implementation using `nlohmann::json`.
- **core::ConfigLoader** – Loads TOML files using `toml++`.
- **core::Logger** – Static class with levels (debug/info/warn/error).
- **core::ThreadPool** - A dynamic, exception-safe thread pool for running tasks concurrently.
- **util::ExpiringCache<K,V>** – TTL-based thread-safe cache.
- **util::CaselessMap** – Case-insensitive `unordered_map`.
- **util::EventQueue** – Thread-safe event queue for dispatching JSON events to registered handlers.
- **iora::IoraService** - A modular C++17 class for orchestrating event-driven microservices and dynamically loading plugins at runtime.

### Module System

- **JSON-RPC Server Module** - A JSON-RPC 2.0 compliant server that can be dynamically loaded as a plugin. Provides method registration, request handling, and statistics via a clean API that only exposes public types.

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
   make
   ```

2. Run all tests:
   ```bash
   make check
   ```

This will build and run the full test suite. No ctest integration is required.

---

## 🚀 Sample Microservice Application

A sample microservice is available under `sample/`, demonstrating:

- **HttpClient** for making HTTP requests  
- **WebhookServer** for receiving webhooks  
- **ShellRunner** for executing shell commands  
- **StateStore** for managing key-value state  
- **ExpiringCache** for TTL-based caching  
- **Logger** for structured logging

### Build and Run

1. Build the sample application:
   ```bash
   cmake --build build --target microservice_example
   ```

2. Run it:
   ```bash
   ./build/sample/microservice_example
   ```

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
your_project_LDADD = -Lpath/to/iora/build -liora_lib -lcpr -lhttplib -lnlohmann_json
your_project_CPPFLAGS = -Ipath/to/iora/include
```

### Manual Makefile

```makefile
CXXFLAGS += -Ipath/to/iora/include
LDFLAGS += -Lpath/to/iora/build
LDLIBS += -liora_lib -lcpr -lhttplib -lnlohmann_json
```

Compile and link:

```bash
g++ -o your_project your_project.cpp $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
```

---

## 🧮 Optional: Enable tiktoken-cpp for Tokenizer

To use exact token counting via `tiktoken-cpp`:

### Install tiktoken-cpp

```bash
git clone https://github.com/gh-markt/tiktoken.git
cd tiktoken
mkdir build && cd build
cmake ..
make
sudo make install
```

### CMake Auto-detection

- If `tiktoken-cpp` is installed system-wide, it will be auto-linked.
- Otherwise, the fallback estimator will be used.
- Detected builds define the `IORA_USE_TIKTOKEN` macro.

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

---

## 📝 License

Iora is licensed under the [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/).  
You may use, modify, and redistribute the code under the terms of the MPL 2.0 license.

See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for more information and attributions for third-party dependencies.