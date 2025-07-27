# Iora

**Iora** is a modern **C++17 single-header microservice foundation library** designed for lightweight, readable, and modular code. It provides components for HTTP services, webhook handling, shell execution, configuration, caching, and pluggable state storage — making it a solid base for event-driven, embedded, or general-purpose applications.

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

- **http::HttpClient** – Wraps `cpr` to call JSON REST APIs.
- **http::WebhookServer** – Wraps `cpp-httplib` to handle POST webhooks.
- **shell::ShellRunner** – Executes Linux shell commands and captures stdout.
- **state::StateStore** – Abstract KV store with disk-backed implementation using `nlohmann::json`.
- **config::ConfigLoader** – Loads TOML files using `toml++`.
- **util::CliParser** – Parses key:value or JSON CLI output.
- **util::ExpiringCache<K,V>** – TTL-based thread-safe cache.
- **util::CaselessMap** – Case-insensitive `unordered_map`.
- **log::Logger** – Static class with levels (debug/info/warn/error).

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

## 📝 License

Iora is licensed under the [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/).  
You may use, modify, and redistribute the code under the terms of the MPL 2.0 license.

See the [LICENSE](./LICENSE) and [NOTICE](./NOTICE) files for more information and attributions for third-party dependencies.