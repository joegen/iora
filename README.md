# Iora

**Iora** is a modern **C++17 application framework for high-performance networked applications** with **ZERO external dependencies** (except OpenSSL for TLS). Designed for production environments, it provides a unified transport layer, advanced networking capabilities, dynamic plugin system, and comprehensive tooling — making it ideal for distributed systems, API gateways, real-time applications, and beyond.

## 📖 Table of Contents

- [🐦 What's In The Name?](#-whats-in-the-name)
- [🎯 Why Choose Iora?](#-why-choose-iora)
- [🎯 Zero External Dependencies](#-zero-external-dependencies)
- [✨ Core Features](#-core-features)
- [🚀 High-Performance JSON Parser](#-high-performance-json-parser)
- [🔧 Production-Ready XML Parser](#-production-ready-xml-parser)
- [⏱️ High-Performance Timer System](#️-high-performance-timer-system)
  - [Advanced Timer Components](#-advanced-timer-components)
  - [Comprehensive Statistics & Monitoring](#-comprehensive-statistics--monitoring)
  - [Usage Examples](#-usage-examples)
  - [Performance Characteristics](#-performance-characteristics)
- [🔄 Thread-Safe Blocking Queue](#-thread-safe-blocking-queue)
  - [Core Features](#-core-features-2)
  - [Key Operations](#️-key-operations)
  - [Use Cases](#-use-cases)
  - [Advanced Features](#-advanced-features-1)
  - [Performance Characteristics](#-performance-characteristics-1)
  - [Best Practices](#-best-practices-1)
- [🌐 Unified Network Transport System](#-unified-network-transport-system)
  - [Core Architecture](#-core-architecture)
  - [Transport Capabilities](#️-transport-capabilities)
  - [Comprehensive Statistics](#-comprehensive-statistics)
  - [Advanced Features](#-advanced-features)
  - [Protocol Support](#️-protocol-support)
- [🏗️ Transport Architecture & Relationships](#️-transport-architecture--relationships)
  - [Architectural Overview](#-architectural-overview)
  - [Component Relationships](#-component-relationships)
  - [Key Design Patterns](#-key-design-patterns)
  - [Choosing the Right Abstraction Level](#-choosing-the-right-abstraction-level)
  - [Usage Examples](#-usage-examples)
  - [Architecture Benefits](#️-architecture-benefits)
- [🛡️ Circuit Breaker & Health Monitoring](#️-circuit-breaker--health-monitoring)
  - [Circuit Breaker System](#-circuit-breaker-system)
  - [Connection Health Monitoring](#-connection-health-monitoring)
  - [Production Integration](#-production-integration)
  - [Best Practices](#-best-practices)
- [🌍 Production-Ready DNS Client System](#-production-ready-dns-client-system)
  - [Key Achievements](#-key-achievements)
  - [Supported DNS Record Types](#-supported-dns-record-types)
  - [DnsClient - The Ultimate DNS Client](#-dnsclient---the-ultimate-dns-client)
  - [Production-Grade Security Features](#️-production-grade-security-features)
  - [Advanced Async Cancellation](#-advanced-async-cancellation)
  - [Intelligent Caching System](#️-intelligent-caching-system)
  - [DNS Record Structures](#-dns-record-structures)
  - [Usage Examples](#-usage-examples)
  - [Key Features](#-key-features)
  - [Architecture Benefits](#️-architecture-benefits)
- [🌐 HTTP Client & Server](#-http-client--server)
  - [HttpClient - Advanced HTTP Client](#httpclient---advanced-http-client)
  - [HttpClientPool - Connection Pool Manager](#httpclientpool---connection-pool-manager)
  - [WebhookServer - Production HTTP Server](#webhookserver---production-http-server)
  - [Configuration & TLS Support](#configuration--tls-support)
  - [Usage Examples](#usage-examples)
- [🔌 Available Plugins](#-available-plugins)
- [🛠️ Build Instructions](#️-build-instructions)
- [📦 Installation](#-installation)
- [✅ Run Tests](#-run-tests)
- [🚀 Sample Microservice Plugin](#-sample-microservice-plugin)
- [🔗 Linking to Iora](#-linking-to-iora)
- [🔌 Plugin Support](#-plugin-support)
  - [How It Works](#how-it-works)
  - [Example Plugin](#example-plugin)
  - [Plugin Dependency System](#plugin-dependency-system)
  - [Configuration](#configuration)
  - [Logging and Error Handling](#logging-and-error-handling)
  - [JSON-RPC Server Module](#json-rpc-server-module)
- [🔒 Thread-Safe Plugin API Access](#-thread-safe-plugin-api-access)
- [📝 License](#-license)

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
- **network::HttpClientPool** — Thread-safe HTTP client pool with RAII-based resource management
- **network::WebhookServer** — Production-grade webhook server with TLS and authentication
- **network::CircuitBreaker** — Prevent cascade failures with configurable circuit breaking
- **network::ConnectionHealth** — Real-time connection monitoring and automatic recovery

### 💾 Storage & State Management  
- **storage::JsonFileStore** — JSON-backed persistent key-value store with background flushing
- **storage::ConcreteStateStore** — Thread-safe in-memory key-value store with case-insensitive keys
- **util::ExpiringCache<K,V>** — Thread-safe TTL cache with LRU eviction policies

### 🛠️ Development & Operations
- **core::ThreadPool** — Dynamic, exception-safe thread pool with work stealing
- **core::BlockingQueue<T>** — Thread-safe bounded queue with blocking operations and timeout support
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

Iora includes a **sophisticated timer service** designed for high-throughput microservices that need precise timing and scheduling capabilities with enterprise-grade reliability and monitoring.

### ⚡ **Core Architecture**
- **Linux-Optimized** — Built on timerfd, epoll, and eventfd for maximum performance
- **High-Resolution** — Microsecond precision with steady clock guarantees  
- **Thread-Safe** — All operations are thread-safe by design with lock-free paths
- **Scalable** — Handle millions of concurrent timers efficiently
- **Exception-Safe** — Comprehensive error handling with configurable policies

### 🛠️ **Advanced Timer Components**

#### **TimerService - Single-Threaded High Performance**
```cpp
class TimerService {
public:
    // Configuration for fine-tuning behavior
    struct Config {
        std::uint32_t maxConcurrentTimers{100000};     // Resource limits
        std::string threadName{"TimerService"};         // Thread identification
        bool enableStatistics{false};                  // Performance monitoring
        std::chrono::microseconds resolutionHint{1000}; // Timer resolution
        ErrorHandlerFunc errorHandler;                  // Custom error handling
        int threadPriority{0};                         // Thread priority (-20 to 19)
    };
    
    // High-performance timer scheduling
    template<typename Rep, typename Period, typename Handler>
    TimerId scheduleAfter(std::chrono::duration<Rep, Period> delay, Handler&& handler);
    
    template<typename Rep, typename Period, typename Handler>
    TimerId schedulePeriodic(std::chrono::duration<Rep, Period> interval, Handler&& handler);
    
    // Advanced scheduling with absolute time
    template<typename Clock, typename Duration, typename Handler>
    TimerId scheduleAt(std::chrono::time_point<Clock, Duration> timePoint, Handler&& handler);
    
    // Timer management
    bool cancel(TimerId id);
    bool reschedule(TimerId id, std::chrono::microseconds newDelay);
    
    // Performance monitoring
    const TimerStats& getStats() const;
    void resetStats();
};
```

#### **TimerServicePool - Distributed Load Balancing**
```cpp
class TimerServicePool {
public:
    // Create pool with multiple timer threads
    TimerServicePool(std::size_t numThreads, const TimerService::Config& config = {});
    
    // Get service for round-robin distribution
    TimerService& getService();
    
    // Get specific service by index
    TimerService& getService(std::size_t index);
    
    // Pool-wide operations
    void start();
    void stop();
    void waitForStop();
    
    // Aggregate statistics across all services
    TimerStats getAggregateStats() const;
    
    // Load balancing information
    std::vector<std::size_t> getServiceLoads() const;
    TimerService& getLeastLoadedService();
};
```

#### **SteadyTimer - ASIO-Compatible Interface**
```cpp
class SteadyTimer {
public:
    explicit SteadyTimer(TimerService& service);
    
    // ASIO-style async operations
    template<typename Rep, typename Period>
    void expiresAfter(std::chrono::duration<Rep, Period> duration);
    
    template<typename Clock, typename Duration>
    void expiresAt(std::chrono::time_point<Clock, Duration> timePoint);
    
    template<typename WaitHandler>
    void asyncWait(WaitHandler&& handler);
    
    // Synchronous wait operations
    void wait();
    std::error_code wait(std::error_code& ec);
    
    // Timer management
    std::size_t cancel();
    std::size_t cancel(std::error_code& ec);
    
    // Time remaining
    std::chrono::microseconds timeRemaining() const;
    bool hasExpired() const;
};
```

### 📊 **Comprehensive Statistics & Monitoring**

```cpp
struct TimerStats {
    // Basic counters
    std::atomic<std::uint64_t> timersScheduled{0};      // Total scheduled
    std::atomic<std::uint64_t> timersCanceled{0};       // Canceled before execution
    std::atomic<std::uint64_t> timersExecuted{0};       // Successfully executed
    std::atomic<std::uint64_t> timersExpired{0};        // Expired (timeout)
    std::atomic<std::uint64_t> periodicTimersActive{0}; // Active periodic timers
    
    // Error tracking
    std::atomic<std::uint64_t> exceptionsSwallowed{0};  // Handler exceptions caught
    std::atomic<std::uint64_t> systemErrors{0};         // System call failures
    
    // Performance metrics
    std::atomic<std::uint64_t> heapOperations{0};       // Priority queue operations
    std::atomic<std::uint64_t> epollWaits{0};           // Event loop iterations
    std::atomic<std::uint64_t> eventfdWakeups{0};       // Cross-thread wakeups
    std::atomic<std::uint64_t> timerfdTriggers{0};      // Timer file descriptor events
    
    // Handler execution timing
    std::atomic<std::uint64_t> totalHandlerExecutionTimeNs{0};
    std::atomic<std::uint64_t> maxHandlerExecutionTimeNs{0};
    std::atomic<std::uint64_t> avgHandlerExecutionTimeNs{0};
    
    std::chrono::steady_clock::time_point startTime;
};
```

### 🚀 **Usage Examples**

#### **Basic Timer Operations**
```cpp
#include "iora/iora.hpp"
using namespace iora::core;

// Create timer service with monitoring enabled
TimerService::Config config;
config.enableStatistics = true;
config.maxConcurrentTimers = 50000;
config.threadName = "AppTimers";

TimerService service(config);

// Schedule one-shot timer
auto oneShot = service.scheduleAfter(std::chrono::seconds(5), []() {
    std::cout << "One-shot timer fired!" << std::endl;
});

// Schedule periodic timer
auto periodic = service.schedulePeriodic(std::chrono::milliseconds(100), []() {
    std::cout << "Periodic tick" << std::endl;
});

// Schedule at absolute time
auto tomorrow = std::chrono::steady_clock::now() + std::chrono::hours(24);
auto absolute = service.scheduleAt(tomorrow, []() {
    std::cout << "Daily maintenance task" << std::endl;
});

// Cancel timers
service.cancel(oneShot);
service.cancel(periodic);
```

#### **High-Throughput Timer Pool**
```cpp
// Create pool with 8 worker threads
TimerServicePool pool(8, config);
pool.start();

// Distribute timers across the pool
for (int i = 0; i < 1000000; ++i) {
    auto& service = pool.getService(); // Round-robin assignment
    service.scheduleAfter(std::chrono::milliseconds(i % 10000), [i]() {
        processTask(i);
    });
}

// Monitor pool performance
auto stats = pool.getAggregateStats();
auto loads = pool.getServiceLoads();

std::cout << "Total timers scheduled: " << stats.timersScheduled << std::endl;
std::cout << "Average handler time: " << stats.avgHandlerExecutionTimeNs << "ns" << std::endl;
std::cout << "Service loads: ";
for (auto load : loads) {
    std::cout << load << " ";
}
std::cout << std::endl;
```

#### **ASIO-Compatible Interface**
```cpp
// Create ASIO-style timer
SteadyTimer timer(service);

// Async wait with callback
timer.expiresAfter(std::chrono::seconds(2));
timer.asyncWait([](std::error_code ec) {
    if (!ec) {
        std::cout << "ASIO-style timer completed!" << std::endl;
    } else {
        std::cout << "Timer was canceled: " << ec.message() << std::endl;
    }
});

// Synchronous wait
SteadyTimer syncTimer(service);
syncTimer.expiresAfter(std::chrono::milliseconds(500));
syncTimer.wait(); // Blocks until timer expires
std::cout << "Sync timer completed!" << std::endl;

// Check time remaining
auto remaining = syncTimer.timeRemaining();
std::cout << "Time remaining: " << remaining.count() << "μs" << std::endl;
```

#### **Error Handling & Resource Management**
```cpp
// Custom error handler
auto errorHandler = [](TimerError error, const std::string& message, int errno_val) {
    std::cerr << "Timer error [" << static_cast<int>(error) << "]: " 
              << message << std::endl;
    if (error == TimerError::ResourceExhausted) {
        // Implement backpressure or cleanup logic
        cleanupExpiredTimers();
    }
};

TimerService::Config config;
config.errorHandler = errorHandler;
config.maxConcurrentTimers = 10000; // Set reasonable limits

TimerService service(config);

// Handle timer exceptions
try {
    auto id = service.scheduleAfter(std::chrono::microseconds(1), []() {
        throw std::runtime_error("Handler failed!");
    });
} catch (const TimerException& e) {
    std::cout << "Timer error: " << e.what() 
              << " [code: " << static_cast<int>(e.code()) << "]" << std::endl;
}
```

#### **Performance Monitoring & Tuning**
```cpp
// Monitor timer service performance
void monitorTimerPerformance(const TimerService& service) {
    const auto& stats = service.getStats();
    auto runtime = std::chrono::steady_clock::now() - stats.startTime;
    auto runtimeSeconds = std::chrono::duration_cast<std::chrono::seconds>(runtime).count();
    
    std::cout << "=== Timer Service Performance Report ===" << std::endl;
    std::cout << "Runtime: " << runtimeSeconds << " seconds" << std::endl;
    std::cout << "Timers scheduled: " << stats.timersScheduled << std::endl;
    std::cout << "Timers executed: " << stats.timersExecuted << std::endl;
    std::cout << "Timers canceled: " << stats.timersCanceled << std::endl;
    std::cout << "Active periodic timers: " << stats.periodicTimersActive << std::endl;
    
    if (stats.timersExecuted > 0) {
        auto avgHandlerTime = stats.avgHandlerExecutionTimeNs.load();
        auto maxHandlerTime = stats.maxHandlerExecutionTimeNs.load();
        
        std::cout << "Average handler time: " << (avgHandlerTime / 1000.0) << "μs" << std::endl;
        std::cout << "Max handler time: " << (maxHandlerTime / 1000.0) << "μs" << std::endl;
    }
    
    std::cout << "System errors: " << stats.systemErrors << std::endl;
    std::cout << "Handler exceptions: " << stats.exceptionsSwallowed << std::endl;
    std::cout << "Heap operations: " << stats.heapOperations << std::endl;
}
```

### 🎯 **Performance Characteristics**
- **Ultra-Low Latency** — Sub-millisecond scheduling overhead
- **High Throughput** — Millions of timers per second
- **Memory Efficient** — Zero allocation in timer execution hot path
- **CPU Efficient** — Event-driven architecture with minimal system calls
- **Predictable** — Bounded execution time with resource limits
- **Scalable** — Linear scaling with CPU cores in pool mode

### 🏗️ **Architecture Benefits**
- **No External Dependencies** — Pure C++17 implementation with Linux system calls
- **Production Ready** — Used in high-frequency trading and real-time systems
- **Exception Safe** — Comprehensive error handling with recovery strategies
- **Resource Controlled** — Configurable limits prevent resource exhaustion
- **Monitoring Ready** — Built-in statistics for observability and debugging

---

## 🔄 Thread-Safe Blocking Queue

Iora's **BlockingQueue<T>** provides a production-ready, thread-safe bounded queue for multi-producer, multi-consumer scenarios. Designed for high-throughput concurrent systems requiring reliable work distribution and backpressure management.

### ⚡ **Core Features**

- **Blocking Operations** — Producers block when full, consumers block when empty
- **Timeout Support** — All operations support configurable timeouts
- **Bounded Capacity** — Enforced maximum size prevents memory exhaustion
- **No Exceptions on Dequeue** — Returns bool for robust error handling
- **Move Semantics** — Efficient zero-copy operations for large objects
- **Graceful Shutdown** — close() wakes all blocked threads for clean teardown
- **Header-Only** — Single template header with zero dependencies

### 🛠️ **Key Operations**

```cpp
#include "iora/core/blocking_queue.hpp"
using namespace iora::core;

// Create queue with capacity of 100 items
BlockingQueue<WorkItem> queue(100);

// Producer thread - blocking enqueue
WorkItem item{42, "data"};
if (queue.queue(item)) {
    // Item successfully queued
}

// Consumer thread - blocking dequeue
WorkItem result;
if (queue.dequeue(result)) {
    // Process result
}

// Non-blocking operations
if (queue.tryQueue(item)) {
    // Queued without blocking
}

if (queue.tryDequeue(result)) {
    // Dequeued without blocking
}

// Timeout-based operations
if (queue.dequeue(result, std::chrono::seconds(5))) {
    // Got item within 5 seconds
} else {
    // Timeout or queue closed
}

// Graceful shutdown
queue.close();  // Wakes all waiting threads
```

### 🎯 **Use Cases**

#### **Producer-Consumer Pattern**
```cpp
// Multiple producers
std::vector<std::thread> producers;
for (int i = 0; i < 4; ++i) {
    producers.emplace_back([&queue, i]() {
        for (int j = 0; j < 1000; ++j) {
            WorkItem item{i, j};
            queue.queue(std::move(item));
        }
    });
}

// Multiple consumers
std::vector<std::thread> consumers;
for (int i = 0; i < 4; ++i) {
    consumers.emplace_back([&queue]() {
        WorkItem item;
        while (queue.dequeue(item, std::chrono::seconds(1))) {
            processWork(item);
        }
    });
}
```

#### **Backpressure Handling**
```cpp
// Try to enqueue with immediate failure on full queue
if (!queue.tryQueue(item)) {
    // Queue full - apply backpressure
    metrics.incrementDropped();
    logWarning("Queue full, dropping item");
}

// Or with timeout-based backpressure
if (!queue.tryQueue(item, std::chrono::milliseconds(100))) {
    // Couldn't enqueue within 100ms - system overloaded
    sendServiceUnavailable();
}
```

#### **Work Distribution with ThreadPool**
```cpp
BlockingQueue<Task> taskQueue(1000);
ThreadPool workers(8, 16);

// Dispatcher thread
std::thread dispatcher([&]() {
    Task task;
    while (taskQueue.dequeue(task)) {
        workers.enqueue([t = std::move(task)]() {
            t.execute();
        });
    }
});

// Producers add work to queue
taskQueue.queue(Task{"job1"});
taskQueue.queue(Task{"job2"});
```

### 🔧 **Advanced Features**

- **Capacity Management**: `size()`, `empty()`, `full()`, `capacity()`
- **Close Semantics**: Existing items can be dequeued after `close()`
- **FIFO Ordering**: Guaranteed first-in-first-out ordering
- **Type Safety**: Template-based, works with any movable or copyable type
- **Thread Safety**: All operations are fully thread-safe
- **Zero Allocation**: No dynamic allocation after construction

### 📊 **Performance Characteristics**

- **Lock-Free Waiting**: Uses condition variables for efficient thread synchronization
- **Minimal Contention**: Separate locks for not-empty and not-full conditions
- **Cache-Friendly**: Uses std::deque for optimal cache performance
- **Move-Optimized**: Leverages move semantics to avoid copies

### ⚠️ **Best Practices**

```cpp
// ✅ Good: Check return values
WorkItem item;
if (queue.dequeue(item)) {
    process(item);
} else {
    // Queue closed and empty
}

// ✅ Good: Use timeouts for robustness
if (queue.dequeue(item, std::chrono::seconds(30))) {
    process(item);
} else {
    // Handle timeout
}

// ✅ Good: Graceful shutdown
queue.close();  // Signal shutdown
// Drain remaining items
while (queue.tryDequeue(item)) {
    process(item);
}

// ❌ Bad: Ignoring return values
queue.dequeue(item);  // May fail if closed!
process(item);  // Undefined behavior

// ❌ Bad: Infinite blocking without shutdown handling
while (true) {
    queue.dequeue(item);  // Will hang if queue closed and empty
    process(item);
}
```

---

## 🌐 Unified Network Transport System

Iora's **UnifiedSharedTransport** provides a sophisticated, high-performance transport layer that abstracts TCP, TLS, and UDP protocols behind a single unified interface. Built for production environments requiring both high throughput and low latency.

### ⚡ **Core Architecture**

- **Protocol Agnostic** — Single API for TCP, TLS, and UDP operations
- **Hybrid Sync/Async** — Both blocking and non-blocking I/O patterns
- **Linux Optimized** — Built on epoll, eventfd, and timerfd for maximum performance
- **Thread-Safe** — Concurrent operations with operation queueing
- **Connection Management** — Automatic lifecycle management with health monitoring

### 🛡️ **Transport Capabilities**

Each transport exposes its capabilities through a capability system:

```cpp
enum class Capability : std::uint32_t {
    None = 0,
    HasTls = 1 << 0,                    // TLS/SSL support
    IsConnectionOriented = 1 << 1,      // TCP-style connections
    HasConnectViaListener = 1 << 2,     // Server-side connections
    SupportsKeepalive = 1 << 3,         // Connection keep-alive
    SupportsBatchSend = 1 << 4,         // Batched send operations
    SupportsSyncOperations = 1 << 5,    // Blocking operations
    SupportsReadModes = 1 << 6          // Exclusive read modes
};
```

### 📊 **Comprehensive Statistics**

The transport layer provides detailed operational metrics:

```cpp
struct UnifiedStats {
    std::uint64_t accepted{0};          // Connections accepted
    std::uint64_t connected{0};         // Outbound connections made
    std::uint64_t closed{0};            // Connections closed
    std::uint64_t errors{0};            // Error count
    std::uint64_t tlsHandshakes{0};     // TLS handshakes completed
    std::uint64_t tlsFailures{0};       // TLS handshake failures
    std::uint64_t bytesIn{0};           // Bytes received
    std::uint64_t bytesOut{0};          // Bytes sent
    std::uint64_t backpressureCloses{0}; // Connections closed due to backpressure
    std::size_t sessionsCurrent{0};     // Active sessions
    std::size_t sessionsPeak{0};        // Peak concurrent sessions
};
```

### 🔧 **Usage Examples**

```cpp
#include "iora/iora.hpp"
using namespace iora::network;

// Create unified transport for TCP
auto transport = UnifiedSharedTransport::createTcp();

// Server: Listen for connections
transport->listen("0.0.0.0", 8080, 
    [](SessionId sessionId, const std::string& data) {
        // Handle incoming data
        std::cout << "Received: " << data << std::endl;
    });

// Client: Connect and send data
auto sessionId = transport->connect("127.0.0.1", 8080);
transport->send(sessionId, "Hello, Server!");

// Check transport capabilities
auto caps = transport->getCapabilities();
if (any(caps & Capability::HasTls)) {
    std::cout << "TLS support available" << std::endl;
}

// Monitor performance
auto stats = transport->getStats();
std::cout << "Active sessions: " << stats.sessionsCurrent << std::endl;
std::cout << "Bytes transferred: " << stats.bytesIn + stats.bytesOut << std::endl;
```

### 🚀 **Advanced Features**

#### **Exclusive Read Modes**
Control how data is processed to prevent race conditions:
```cpp
transport->setExclusiveReadMode(sessionId, true);
// Only one thread processes data for this session
```

#### **Batch Operations**
Optimize throughput with batched sends:
```cpp
if (any(caps & Capability::SupportsBatchSend)) {
    std::vector<std::pair<SessionId, std::string>> batch = {
        {session1, "Message 1"},
        {session2, "Message 2"},
        {session3, "Message 3"}
    };
    transport->sendBatch(batch);
}
```

#### **Connection Health Monitoring**
Monitor connection health with automatic recovery:
```cpp
transport->setHealthCheckInterval(std::chrono::seconds(30));
transport->onConnectionHealthChanged([](SessionId id, bool healthy) {
    if (!healthy) {
        std::cout << "Session " << id << " is unhealthy" << std::endl;
    }
});
```

### 🏗️ **Protocol Support**

#### **TCP Transport**
```cpp
auto tcpTransport = UnifiedSharedTransport::createTcp();
// Full-duplex, reliable, connection-oriented
```

#### **TLS Transport**
```cpp
TlsConfig tlsConfig;
tlsConfig.certFile = "/path/to/cert.pem";
tlsConfig.keyFile = "/path/to/key.pem";
auto tlsTransport = UnifiedSharedTransport::createTls(tlsConfig);
// TCP with TLS encryption
```

#### **UDP Transport**
```cpp
auto udpTransport = UnifiedSharedTransport::createUdp();
// Connectionless, fast, best-effort delivery
```

### 🎯 **Performance Characteristics**

- **High Throughput** — Optimized for millions of concurrent connections
- **Low Latency** — Sub-millisecond response times with proper tuning
- **Memory Efficient** — Connection pooling and buffer reuse
- **CPU Efficient** — Event-driven architecture minimizes context switches
- **Scalable** — Linear performance scaling with CPU cores

---

## 🏗️ Transport Architecture & Relationships

Iora's transport system follows a **layered architecture** that provides maximum flexibility while maintaining high performance. Understanding these relationships helps you choose the right abstraction level for your application needs.

### **🔧 Architectural Overview**

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                        │
├─────────────────────────────────────────────────────────────┤
│         UnifiedSharedTransport (High-Level Facade)         │
├─────────────────────────────────────────────────────────────┤
│            SyncAsyncTransport (Sync/Async Wrapper)         │
├─────────────────────────────────────────────────────────────┤
│    SharedTransport (TCP/TLS)    │  SharedUdpTransport (UDP) │
│         (Base Protocols)        │       (Base Protocols)   │
├─────────────────────────────────────────────────────────────┤
│                  Linux epoll/eventfd/timerfd               │
└─────────────────────────────────────────────────────────────┘
```

### **🎯 Component Relationships**

#### **1. Base Transport Layer**
The foundation providing raw protocol implementations:

**`SharedTransport`** - TCP/TLS Transport
- **Purpose**: High-performance TCP and TLS transport with epoll-based I/O
- **Features**: Single I/O thread, async operations, built-in TLS via OpenSSL
- **Usage**: Direct use for async-only TCP/TLS applications
- **Location**: `include/iora/network/shared_transport.hpp`

**`SharedUdpTransport`** - UDP Transport  
- **Purpose**: UDP transport with session concept for API consistency
- **Features**: Same epoll architecture as TCP, connectionless but tracked
- **Usage**: Direct use for async-only UDP applications
- **Location**: `include/iora/network/shared_transport_udp.hpp`

#### **2. Synchronization Layer**
Adds blocking operations on top of async transports:

**`SyncAsyncTransport`** - Sync/Async Wrapper
- **Purpose**: Provides **synchronous operations** on top of async transports
- **Features**:
  - Exclusive read modes (prevent sync/async conflicts)
  - Cancellable operations without closing connections
  - Connection health monitoring
  - Thread-safe synchronous operations with queueing
- **Design Pattern**: **Composition** - wraps any `ITransportBase` implementation
- **Usage**: When you need both sync and async operations on same transport
- **Location**: `include/iora/network/sync_async_transport.hpp`

#### **3. Adapter Layer**
Normalizes different protocols behind common interfaces:

**`TcpTlsTransportAdapter`** & **`UdpTransportAdapter`**
- **Purpose**: Implement common `ITransport` interface for protocol-specific transports
- **Design Pattern**: **Adapter Pattern** - makes different transports look identical
- **Usage**: Internal - used by UnifiedSharedTransport for protocol abstraction

#### **4. Unified Layer**
Single high-level API for protocol-agnostic applications:

**`UnifiedSharedTransport`** - Protocol-Agnostic Facade
- **Purpose**: Single API for both TCP and UDP with sync/async support
- **Features**:
  - Protocol selection (TCP/UDP) at configuration time
  - Unified configuration combining all layer settings
  - Built on SyncAsyncTransport for dual-mode operations
- **Design Pattern**: **Facade Pattern** - hides complexity of multiple transport layers
- **Usage**: Recommended for most applications requiring protocol flexibility
- **Location**: `include/iora/network/unified_shared_transport.hpp`

### **🔗 Key Design Patterns**

#### **Composition Over Inheritance**
Each layer **contains** rather than **extends** lower layers:
```cpp
// UnifiedSharedTransport contains SyncAsyncTransport
std::unique_ptr<SyncAsyncTransport> _hybrid;

// SyncAsyncTransport contains base transport  
std::unique_ptr<ITransportBase> _transport;

// Adapters contain protocol-specific implementations
SharedTransport _impl;  // in TcpTlsTransportAdapter
SharedUdpTransport _impl;  // in UdpTransportAdapter
```

#### **Strategy Pattern**
Protocol selection is configurable at runtime:
```cpp
enum class Protocol { TCP, UDP };

UnifiedSharedTransport::Config config;
config.protocol = Protocol::TCP;  // or Protocol::UDP
auto transport = std::make_unique<UnifiedSharedTransport>(config);
```

### **🎯 Choosing the Right Abstraction Level**

#### **When to Use Each Layer**

| Layer | Use When | Example Use Cases |
|-------|----------|-------------------|
| **Base** (`SharedTransport`/`SharedUdpTransport`) | You need maximum performance and only async operations | High-frequency trading, real-time data feeds |
| **Sync/Async** (`SyncAsyncTransport`) | You need both sync and async operations on same connection | HTTP servers, database proxies |
| **Unified** (`UnifiedSharedTransport`) | You want protocol abstraction and flexible configuration | Microservices, API gateways |

#### **Performance vs Convenience Trade-offs**

```
Raw Performance    ←  →  Convenience & Features
Base Transport     ←  →  Unified Transport
Async Only        ←  →  Sync + Async
Single Protocol   ←  →  Multi-Protocol
Manual Setup      ←  →  Unified Config
```

### **🚀 Usage Examples**

#### **Base Layer - Maximum Performance**
```cpp
#include "iora/network/shared_transport.hpp"

// Direct use of base transport for async-only TCP
SharedTransport transport;
transport.setCallbacks({
    .onData = [](SessionId sid, const uint8_t* data, size_t len, const IoResult& result) {
        // Handle incoming data asynchronously
    }
});
transport.start();
auto sessionId = transport.connect("api.service.com", 443, TlsMode::Client);
```

#### **Sync/Async Layer - Dual Operations**
```cpp
#include "iora/network/sync_async_transport.hpp"

// Wrap base transport to add synchronous operations
auto baseTransport = std::make_unique<SharedTransport>(config);
SyncAsyncTransport syncAsyncTransport(std::move(baseTransport));

// Use both sync and async operations
syncAsyncTransport.start();
auto sid = syncAsyncTransport.connect("service.com", 80, TlsMode::None);

// Async send
syncAsyncTransport.sendAsync(sid, "GET /", [](SessionId, const SyncResult& result) {
    // Handle async completion
});

// Sync receive  
std::vector<uint8_t> buffer(1024);
auto result = syncAsyncTransport.receiveSync(sid, buffer.data(), buffer.size(), 
                                           std::chrono::seconds(5));
```

#### **Unified Layer - Protocol Abstraction**  
```cpp
#include "iora/network/unified_shared_transport.hpp"

// High-level transport supporting both TCP and UDP
UnifiedSharedTransport::Config config;
config.protocol = UnifiedSharedTransport::Protocol::TCP;
config.connectTimeout = std::chrono::seconds(5);

auto transport = std::make_unique<UnifiedSharedTransport>(config);

// Protocol-agnostic operations
transport->start();
auto sid = transport->connect("api.example.com", 443, TlsMode::Client);

// Can switch between sync and async modes per session
transport->setReadMode(sid, ReadMode::Synchronous);
transport->sendAsync(sid, "request data", [](auto, auto) { /* callback */ });
```

### **🏗️ Architecture Benefits**

#### **Flexibility**
- Choose the abstraction level that matches your performance/convenience needs
- Mix different layers in same application for different use cases
- Easy migration between layers as requirements change

#### **Maintainability**
- Clear separation of concerns between layers
- Each layer can evolve independently
- Testable components with well-defined interfaces

#### **Performance**
- Zero-cost abstractions where possible
- Pay only for features you use
- Direct access to high-performance base transports when needed

#### **Safety**
- Synchronization layer prevents sync/async conflicts
- Health monitoring and connection lifecycle management
- Graceful error handling and recovery at each layer

This layered architecture ensures that whether you're building a high-frequency trading system requiring maximum performance or a flexible microservice needing protocol abstraction, Iora provides the right tool for the job.

---

## 🛡️ Circuit Breaker & Health Monitoring

Iora provides enterprise-grade **Circuit Breaker** and **Connection Health** systems to prevent cascade failures and ensure system resilience in production environments.

### 🔥 **Circuit Breaker System**

The circuit breaker pattern prevents calls to failing services, allowing them time to recover while protecting your application from cascade failures.

#### **States & Transitions**

```
┌─────────────┐    Failure Rate     ┌─────────────┐
│   CLOSED    │ ───────────────────▶ │    OPEN     │
│  (Normal)   │   Exceeds Threshold  │ (Failing)   │
└─────┬───────┘                      └──────┬──────┘
      │                                     │
      │ Success                             │ Timeout
      │ Threshold                           │ Expires
      │ Reached                             ▼
┌─────▼───────┐                      ┌─────────────┐
│   CLOSED    │ ◄──────────────────── │  HALF-OPEN  │
│             │    Recovery Test      │  (Testing)  │
└─────────────┘      Passes          └─────────────┘
```

#### **Configuration Options**

```cpp
struct CircuitBreakerConfig {
    int failureThreshold{5};              // Failures to trigger open state
    std::chrono::seconds timeout{60};     // Wait time before testing recovery
    int successThreshold{3};              // Successes needed to close circuit
    std::chrono::seconds statisticsWindow{300}; // Window for failure rate calculation
    double failureRateThreshold{0.5};     // Failure rate (0.0-1.0) to trigger open
    int minimumRequests{10};               // Minimum requests before considering rate
};
```

#### **Usage Examples**

```cpp
#include "iora/iora.hpp"
using namespace iora::network;

// Create circuit breaker with custom config
CircuitBreakerConfig config;
config.failureThreshold = 10;
config.timeout = std::chrono::seconds(30);
config.successThreshold = 5;
config.failureRateThreshold = 0.6;  // 60% failure rate

CircuitBreaker breaker(config);

// Use circuit breaker to protect service calls
auto callExternalService = [&]() -> bool {
    if (!breaker.allowRequest()) {
        std::cout << "Circuit breaker is OPEN - failing fast" << std::endl;
        return false;
    }
    
    try {
        // Make your service call
        bool success = makeHttpRequest("https://api.example.com/data");
        
        if (success) {
            breaker.recordSuccess();
            return true;
        } else {
            breaker.recordFailure();
            return false;
        }
    } catch (const std::exception& e) {
        breaker.recordFailure();
        std::cout << "Service call failed: " << e.what() << std::endl;
        return false;
    }
};

// Monitor circuit breaker state
auto state = breaker.getState();
switch (state) {
    case CircuitBreakerState::Closed:
        std::cout << "Circuit breaker: Normal operation" << std::endl;
        break;
    case CircuitBreakerState::Open:
        std::cout << "Circuit breaker: Failing fast, service unavailable" << std::endl;
        break;
    case CircuitBreakerState::HalfOpen:
        std::cout << "Circuit breaker: Testing service recovery" << std::endl;
        break;
}
```

#### **CircuitBreakerManager for Multiple Services**

```cpp
class CircuitBreakerManager {
public:
    // Get or create circuit breaker for a service
    CircuitBreaker& getBreaker(const std::string& serviceName,
                              const CircuitBreakerConfig& config = {});
    
    // Check if any service is failing
    bool hasOpenCircuits() const;
    
    // Get statistics for all circuit breakers
    std::map<std::string, CircuitBreakerStats> getStats() const;
};

// Usage
CircuitBreakerManager manager;

auto& userService = manager.getBreaker("user-service");
auto& paymentService = manager.getBreaker("payment-service");
auto& inventoryService = manager.getBreaker("inventory-service");

// Each service has independent circuit breaker protection
```

### 💗 **Connection Health Monitoring**

The health monitoring system continuously tracks connection health and provides early warning of degraded performance.

#### **Health States**

```cpp
enum class HealthState {
    Healthy,    // Normal operation
    Warning,    // Minor issues detected
    Degraded,   // Performance issues
    Critical,   // Major issues
    Unhealthy   // Connection should be avoided
};
```

#### **HealthMonitor Features**

```cpp
class HealthMonitor {
public:
    struct Config {
        std::chrono::seconds heartbeatInterval{30};      // Health check frequency
        std::chrono::seconds degradedThreshold{5};       // Time before marking degraded
        std::chrono::seconds unhealthyThreshold{15};     // Time before marking unhealthy
        double successRateThreshold{0.95};              // Success rate for healthy state
        int consecutiveFailuresThreshold{3};             // Failures before degraded
        int healthCheckTimeoutMs{5000};                  // Health check timeout
    };
    
    // Monitor connection health
    void startMonitoring(SessionId sessionId);
    void stopMonitoring(SessionId sessionId);
    
    // Get current health state
    HealthState getHealthState(SessionId sessionId) const;
    
    // Register health change callbacks
    void onHealthChanged(std::function<void(SessionId, HealthState, HealthState)> callback);
    
    // Force health check
    void checkHealth(SessionId sessionId);
    
    // Get health statistics
    struct HealthStats {
        std::chrono::steady_clock::time_point lastCheck;
        std::chrono::milliseconds avgResponseTime{0};
        double successRate{0.0};
        int consecutiveFailures{0};
        int totalChecks{0};
    };
    
    HealthStats getHealthStats(SessionId sessionId) const;
};
```

#### **Usage Example**

```cpp
// Create health monitor
HealthMonitor::Config healthConfig;
healthConfig.heartbeatInterval = std::chrono::seconds(15);
healthConfig.degradedThreshold = std::chrono::seconds(3);
healthConfig.successRateThreshold = 0.9;  // 90% success rate

HealthMonitor monitor(healthConfig);

// Monitor connections
auto sessionId = transport->connect("api.service.com", 443);
monitor.startMonitoring(sessionId);

// React to health changes
monitor.onHealthChanged([](SessionId id, HealthState old, HealthState current) {
    switch (current) {
        case HealthState::Healthy:
            std::cout << "Session " << id << " recovered to healthy" << std::endl;
            break;
        case HealthState::Warning:
            std::cout << "Session " << id << " showing warning signs" << std::endl;
            break;
        case HealthState::Degraded:
            std::cout << "Session " << id << " performance degraded" << std::endl;
            break;
        case HealthState::Critical:
            std::cout << "Session " << id << " in critical state" << std::endl;
            break;
        case HealthState::Unhealthy:
            std::cout << "Session " << id << " is unhealthy, consider reconnection" << std::endl;
            // Potentially trigger reconnection logic
            transport->disconnect(id);
            break;
    }
});

// Get health statistics
auto stats = monitor.getHealthStats(sessionId);
std::cout << "Average response time: " << stats.avgResponseTime.count() << "ms" << std::endl;
std::cout << "Success rate: " << (stats.successRate * 100) << "%" << std::endl;
```

### 🏭 **Production Integration**

#### **Combined with HttpClient**

```cpp
// HttpClient with circuit breaker and health monitoring
class ResilientHttpClient {
    CircuitBreakerManager circuitBreakers_;
    HealthMonitor healthMonitor_;
    iora::network::HttpClient httpClient_;
    
public:
    std::optional<HttpResponse> get(const std::string& url) {
        auto& breaker = circuitBreakers_.getBreaker(extractDomain(url));
        
        if (!breaker.allowRequest()) {
            return std::nullopt;  // Circuit breaker open
        }
        
        try {
            auto response = httpClient_.get(url);
            breaker.recordSuccess();
            return response;
        } catch (const std::exception&) {
            breaker.recordFailure();
            return std::nullopt;
        }
    }
};
```

### 🎯 **Best Practices**

1. **Circuit Breaker Configuration**
   - Start with conservative thresholds and adjust based on your service SLAs
   - Use shorter timeouts for non-critical services
   - Monitor failure rates and adjust thresholds accordingly

2. **Health Monitoring**
   - Set heartbeat intervals based on your service's expected response times
   - Use health state changes to trigger automatic remediation
   - Combine with load balancing to route traffic away from unhealthy endpoints

3. **Integration Patterns**
   - Use circuit breakers at service boundaries
   - Implement graceful degradation when circuits are open
   - Log circuit breaker state changes for monitoring and alerting

---

## 🌍 Production-Ready DNS Client System

Iora features a **world-class DNS client implementation** with enterprise-grade capabilities including **RFC 3263 service discovery**, **security-hardened parsing**, **async cancellation**, and **intelligent caching**. Battle-tested and production-ready for the most demanding networked applications.

### 🏆 **Key Achievements**
- ✅ **100% Test Coverage** with comprehensive edge case validation
- ✅ **RFC 3263 Compliant** service discovery (NAPTR → SRV → A/AAAA chains)
- ✅ **Security Hardened** with DNS compression pointer attack prevention
- ✅ **Memory Safe** using RAII and smart pointer architecture
- ✅ **Thread-Safe Cancellation** with immediate future cancellation
- ✅ **Enterprise Caching** with RFC 2308 negative caching support

### 📋 **Supported DNS Record Types**

```cpp
enum class DnsType : std::uint16_t {
    A = 1,        // IPv4 address records
    NS = 2,       // Name server records
    CNAME = 5,    // Canonical name records
    SOA = 6,      // Start of authority records
    PTR = 12,     // Pointer records (reverse DNS)
    MX = 15,      // Mail exchange records
    TXT = 16,     // Text records
    AAAA = 28,    // IPv6 address records
    SRV = 33,     // Service location records
    NAPTR = 35    // Naming Authority Pointer records
};
```

### ⚡ **DnsClient - The Ultimate DNS Client**

Located in `iora::network::DnsClient`, this is our flagship DNS implementation with advanced features:

```cpp
#include "iora/network/dns_client.hpp"
using namespace iora::network;

// Configure the DNS client
dns::DnsConfig config;
config.servers = {"8.8.8.8", "1.1.1.1", "208.67.222.222"};
config.timeout = std::chrono::milliseconds(3000);
config.retryCount = 3;
config.transportMode = dns::DnsTransportMode::Both; // UDP with TCP fallback
config.enableCache = true;
config.maxCacheSize = 10000;

// Create the client
DnsClient client(config);

// === Synchronous DNS Resolution ===
auto ipv4Addresses = client.resolveA("www.example.com");
auto ipv6Addresses = client.resolveAAAA("www.example.com");
auto hostAddresses = client.resolveHostname("www.example.com");
auto srvRecords = client.resolveSRV("_sip._tcp.example.com");
auto naptrRecords = client.resolveNAPTR("example.com");
auto mxRecords = client.resolveMX("example.com");

// === Advanced Service Discovery (RFC 3263) ===
auto serviceResult = client.resolveServiceDomain("example.com", {
    dns::ServiceType::TCP, 
    dns::ServiceType::TLS, 
    dns::ServiceType::UDP
});

// Access prioritized targets for connection attempts
for (const auto& target : serviceResult.targets) {
    std::cout << "Priority: " << target.priority 
              << " Address: " << target.address 
              << " Port: " << target.port << std::endl;
}

// === Asynchronous Operations with Futures ===
auto future = client.resolveAAsync("async.example.com");

// Cancellable futures - perfect for timeouts!
if (future.cancel()) {
    std::cout << "Request cancelled successfully" << std::endl;
}

// Check if the future is ready (non-blocking)
if (future.future.wait_for(std::chrono::seconds(1)) == std::future_status::ready) {
    try {
        auto addresses = future.future.get();
        std::cout << "Resolved " << addresses.size() << " addresses" << std::endl;
    } catch (const dns::DnsResolverException& e) {
        std::cout << "DNS resolution failed: " << e.what() << std::endl;
    }
}

// === Service Discovery with Futures ===
auto serviceFuture = client.resolveServiceDomainFuture("sip.example.com");
auto serviceResult = serviceFuture.future.get(); // Blocks until resolved
```

### 🛡️ **Production-Grade Security Features**

Our DNS client includes enterprise-level security protections:

```cpp
// Automatic protection against DNS compression pointer attacks
// - Prevents infinite loops and malicious pointer chains  
// - Validates compression pointer bounds and targets
// - Allows legitimate 192.x.x.x IP addresses while blocking attacks

// Built-in query validation
// - Prevents DNS cache poisoning attempts
// - Validates response correlation with queries
// - Implements proper NXDOMAIN vs SERVFAIL distinction

// Memory-safe implementation  
// - Zero raw pointers or manual memory management
// - RAII pattern ensures proper cleanup
// - shared_ptr lifetime management for async operations
```

### ⚡ **Advanced Async Cancellation**

Revolutionary cancellation system with immediate responsiveness:

```cpp
// Start multiple DNS queries
auto future1 = client.resolveAAsync("slow-server1.com");
auto future2 = client.resolveServiceDomainFuture("slow-service.com");

// Cancel specific requests (thread-safe)
bool cancelled1 = future1.cancel();
bool cancelled2 = future2.cancel();

// Check cancellation status
if (future1.isCancelled() && future1.isCompleted()) {
    std::cout << "Request 1 successfully cancelled" << std::endl;
}

// Futures become ready immediately after cancellation
assert(future1.future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready);
```

### 🗂️ **Intelligent Caching System**

RFC 2308 compliant negative caching with SOA minimum TTL support:

```cpp
// Cache management
client.clearCache(); // Clear all cached entries
client.removeCacheEntry(dns::DnsQuestion{"example.com", dns::DnsType::A}); // Remove specific entry

// Cache statistics
auto stats = client.getCacheStatistics();
std::cout << "Cache hit ratio: " << stats.hitRatio << std::endl;
std::cout << "Total entries: " << stats.totalEntries << std::endl;

// Negative caching automatically handles:
// - NXDOMAIN responses with proper TTL from SOA minimum
// - Server failure caching with exponential backoff
// - Cache invalidation on network changes
```

### 📊 **DNS Record Structures**

```cpp
// Service record (SRV)
struct SrvRecord {
    std::uint16_t priority;
    std::uint16_t weight;
    std::uint16_t port;
    std::string target;
};

// Mail exchange record (MX)
struct MxRecord {
    std::uint16_t priority;
    std::string exchange;
};

// NAPTR record for advanced routing
struct NaptrRecord {
    std::uint16_t order;
    std::uint16_t preference;
    std::string flags;
    std::string service;
    std::string regexp;
    std::string replacement;
};

// Generic DNS record for advanced queries
struct DnsRecord {
    std::string name;
    DnsType type;
    std::uint32_t ttl;
    std::vector<std::uint8_t> data;
    std::string textRepresentation;
};
```

### 🚀 **Usage Examples**

#### **Basic DNS Resolution**
```cpp
#include "iora/iora.hpp"
using namespace iora::network;

// Create DNS client with custom configuration
DnsClient::Config config;
config.servers = {"8.8.8.8", "1.1.1.1", "208.67.222.222"};  // Google, Cloudflare, OpenDNS
config.timeout = std::chrono::seconds(3);
config.cacheTimeout = std::chrono::seconds(600);  // 10 minutes
config.retryCount = 2;

DnsClient dns(config);

// Resolve IPv4 addresses
auto ipv4Addresses = dns.resolveA("www.example.com");
for (const auto& ip : ipv4Addresses) {
    std::cout << "IPv4: " << ip << std::endl;
}

// Resolve IPv6 addresses
auto ipv6Addresses = dns.resolveAAAA("www.example.com");
for (const auto& ip : ipv6Addresses) {
    std::cout << "IPv6: " << ip << std::endl;
}

// Resolve both IPv4 and IPv6
auto allAddresses = dns.resolveHost("www.example.com");
for (const auto& ip : allAddresses) {
    std::cout << "IP: " << ip << std::endl;
}
```

#### **Service Discovery with SRV Records**
```cpp
// Resolve SIP service endpoints
auto srpRecords = dns.resolveSrv("_sip._tcp.example.com");
for (const auto& srv : srpRecords) {
    std::cout << "SIP server: " << srv.target 
              << ":" << srv.port 
              << " (priority: " << srv.priority 
              << ", weight: " << srv.weight << ")" << std::endl;
}

// Resolve mail servers
auto mxRecords = dns.resolveMx("example.com");
std::sort(mxRecords.begin(), mxRecords.end(), 
          [](const MxRecord& a, const MxRecord& b) {
              return a.priority < b.priority;  // Lower priority = higher preference
          });

for (const auto& mx : mxRecords) {
    std::cout << "Mail server: " << mx.exchange 
              << " (priority: " << mx.priority << ")" << std::endl;
}
```

#### **Advanced DNS Queries**
```cpp
// Text record lookup (often used for domain verification, SPF, etc.)
auto txtRecords = dns.resolveTxt("example.com");
for (const auto& txt : txtRecords) {
    std::cout << "TXT: " << txt << std::endl;
}

// Reverse DNS lookup
auto ptrRecords = dns.resolvePtr("8.8.8.8");
for (const auto& ptr : ptrRecords) {
    std::cout << "PTR: " << ptr << std::endl;  // Should show "dns.google."
}

// NAPTR records for advanced routing (e.g., SIP, email routing)
auto naptrRecords = dns.resolveNaptr("example.com");
for (const auto& naptr : naptrRecords) {
    std::cout << "NAPTR: order=" << naptr.order 
              << " pref=" << naptr.preference
              << " flags=" << naptr.flags
              << " service=" << naptr.service
              << " regexp=" << naptr.regexp
              << " replacement=" << naptr.replacement << std::endl;
}

// CNAME resolution
auto cnameRecords = dns.resolveCname("www.example.com");
for (const auto& cname : cnameRecords) {
    std::cout << "CNAME: " << cname << std::endl;
}
```

#### **Asynchronous DNS Resolution**
```cpp
// Async A record resolution
dns.resolveAAsync("www.example.com", [](const std::vector<std::string>& addresses) {
    std::cout << "Async A resolution completed:" << std::endl;
    for (const auto& ip : addresses) {
        std::cout << "  IPv4: " << ip << std::endl;
    }
});

// Async host resolution with error handling
dns.resolveHostAsync("www.example.com", 
    [](const std::vector<std::string>& addresses) {
        if (addresses.empty()) {
            std::cout << "No addresses found" << std::endl;
        } else {
            std::cout << "Found " << addresses.size() << " addresses:" << std::endl;
            for (const auto& ip : addresses) {
                std::cout << "  IP: " << ip << std::endl;
            }
        }
    });

// Async SRV resolution
dns.resolveSrvAsync("_sip._tcp.example.com", 
    [](const std::vector<SrvRecord>& records) {
        std::cout << "SRV resolution completed, found " 
                  << records.size() << " records:" << std::endl;
        for (const auto& srv : records) {
            std::cout << "  " << srv.target << ":" << srv.port 
                      << " (pri: " << srv.priority 
                      << ", weight: " << srv.weight << ")" << std::endl;
        }
    });
```

#### **Cache Management & Performance Monitoring**
```cpp
// Monitor DNS performance
auto stats = dns.getStats();
std::cout << "=== DNS Performance Statistics ===" << std::endl;
std::cout << "Total queries: " << stats.totalQueries << std::endl;
std::cout << "Cache hits: " << stats.cacheHits << std::endl;
std::cout << "Cache misses: " << stats.cacheMisses << std::endl;
std::cout << "Cache hit ratio: " << (stats.cacheHitRatio * 100) << "%" << std::endl;
std::cout << "Timeouts: " << stats.timeouts << std::endl;
std::cout << "Errors: " << stats.errors << std::endl;

// Cache management
std::cout << "Current cache size: " << dns.getCacheSize() << " entries" << std::endl;

// Clear specific domain from cache
dns.clearCache("www.example.com");

// Clear entire cache
dns.clearCache();

// Reset statistics
dns.resetStats();
```

#### **Production DNS Client with Fallback**
```cpp
class ProductionDnsResolver {
private:
    DnsClient primaryDns_;
    DnsClient fallbackDns_;
    
public:
    ProductionDnsResolver() {
        // Primary DNS with public resolvers
        DnsClient::Config primaryConfig;
        primaryConfig.servers = {"8.8.8.8", "1.1.1.1", "208.67.222.222"};
        primaryConfig.timeout = std::chrono::seconds(2);
        primaryConfig.retryCount = 2;
        primaryDns_ = DnsClient(primaryConfig);
        
        // Fallback DNS with different servers
        DnsClient::Config fallbackConfig;
        fallbackConfig.servers = {"9.9.9.9", "149.112.112.112"}; // Quad9
        fallbackConfig.timeout = std::chrono::seconds(5);
        fallbackConfig.retryCount = 3;
        fallbackDns_ = DnsClient(fallbackConfig);
    }
    
    std::vector<std::string> resolveWithFallback(const std::string& hostname) {
        try {
            auto result = primaryDns_.resolveHost(hostname);
            if (!result.empty()) {
                return result;
            }
        } catch (const std::exception& e) {
            std::cout << "Primary DNS failed: " << e.what() 
                      << ", trying fallback..." << std::endl;
        }
        
        // Try fallback DNS
        try {
            return fallbackDns_.resolveHost(hostname);
        } catch (const std::exception& e) {
            std::cout << "Fallback DNS also failed: " << e.what() << std::endl;
            return {};
        }
    }
};
```

### 🎯 **Key Features**

#### **TTL-Aware Caching**
- Respects DNS record TTL values for cache expiration
- Configurable cache timeout for custom cache policies
- Memory-efficient cache with size limits
- Per-domain cache invalidation

#### **Multi-Server Support**
- Automatic failover between DNS servers
- Configurable retry logic with exponential backoff
- Round-robin server selection for load distribution
- Server health monitoring and automatic recovery

#### **Performance Optimization**
- Concurrent query processing for multiple domains
- Intelligent cache preloading for frequently accessed domains
- Connection pooling for DNS server connections
- Query deduplication to prevent redundant requests

#### **Production Features**
- Comprehensive error handling with detailed error codes
- Request timeout management with configurable limits
- Statistics collection for monitoring and debugging
- Thread-safe operations for concurrent access

### 🏗️ **Architecture Benefits**
- **Zero External Dependencies** — Built on Iora's transport layer
- **High Performance** — Sub-millisecond cache lookup times
- **Reliability** — Multi-server failover and retry logic
- **Scalability** — Efficient caching reduces DNS server load
- **Observability** — Built-in statistics for monitoring and alerting

---

## 🌐 HTTP Client & Server

Iora provides production-ready HTTP client and server implementations with **zero external dependencies** (except OpenSSL for TLS). Built on the unified transport layer, they offer advanced features including connection pooling, TLS support, JSON handling, and comprehensive error management.

### HttpClient - Advanced HTTP Client

The `HttpClient` provides a powerful, thread-safe HTTP client with connection pooling, automatic retries, and built-in JSON support.

#### 🎯 **Core Features**
- **Connection Pooling** — Automatic connection reuse and lifecycle management
- **TLS/HTTPS Support** — Full certificate validation and client certificate support
- **Built-in JSON Support** — Direct JSON request/response handling with Iora's parser
- **Automatic Retries** — Configurable retry logic with exponential backoff
- **DNS Integration** — Uses Iora's advanced DNS client for domain resolution
- **Thread Safety** — Concurrent requests from multiple threads
- **Timeout Management** — Separate connect and request timeouts
- **Header Management** — Full HTTP header support with custom user agents

#### 📊 **Configuration Options**

```cpp
iora::network::HttpClient::Config config;
config.connectTimeout = std::chrono::milliseconds(2000);  // Connection timeout
config.requestTimeout = std::chrono::milliseconds(5000);  // Request timeout  
config.maxRedirects = 5;                                  // Maximum redirects to follow
config.followRedirects = true;                            // Enable redirect following
config.userAgent = "MyApp/1.0";                          // Custom user agent
config.reuseConnections = true;                           // Enable connection pooling
config.connectionIdleTimeout = std::chrono::seconds(300); // Idle connection timeout

// JSON parsing limits
config.jsonConfig.maxPayloadSize = 50 * 1024 * 1024;     // 50MB max JSON payload
config.jsonConfig.parseLimits.maxDepth = 64;             // Maximum nesting depth

auto client = iora::network::HttpClient(config);
```

#### 🚀 **Usage Examples**

**Basic HTTP Requests:**
```cpp
#include "iora/iora.hpp"

// Create client with default configuration
auto client = iora::IoraService::instanceRef().makeHttpClient();

// Simple GET request
auto response = client.get("https://api.example.com/users");
if (response.success()) {
    std::cout << "Response: " << response.body << std::endl;
    std::cout << "Status: " << response.statusCode << std::endl;
}

// POST request with JSON data
iora::parsers::Json requestData = iora::parsers::Json::object({
    {"name", "John Doe"},
    {"email", "john@example.com"}
});

auto postResponse = client.postJson("https://api.example.com/users", requestData);
if (postResponse.success()) {
    std::cout << "User created successfully!" << std::endl;
}

// Custom headers
std::map<std::string, std::string> headers = {
    {"Authorization", "Bearer token123"},
    {"X-API-Version", "v1"}
};

auto authResponse = client.get("https://api.example.com/protected", headers);
```

**Advanced Usage with TLS:**
```cpp
// Configure TLS for client certificates
iora::network::HttpClient::TlsConfig tlsConfig;
tlsConfig.caFile = "/path/to/ca-cert.pem";
tlsConfig.clientCertFile = "/path/to/client-cert.pem"; 
tlsConfig.clientKeyFile = "/path/to/client-key.pem";
tlsConfig.verifyPeer = true;

client.setTlsConfig(tlsConfig);

// Secure request with client certificate
auto secureResponse = client.get("https://secure-api.example.com/data");
```

**Error Handling and Retries:**
```cpp
try {
    // Request with automatic retries
    auto response = client.get("https://unreliable-api.example.com/data", {}, 3);
    
    if (!response.success()) {
        std::cerr << "Request failed with status: " << response.statusCode 
                  << " - " << response.statusText << std::endl;
    }
} catch (const std::exception& e) {
    std::cerr << "HTTP request error: " << e.what() << std::endl;
}
```

### HttpClientPool - Connection Pool Manager

The `HttpClientPool` provides a thread-safe pool of reusable `HttpClient` instances with automatic lifecycle management through RAII wrappers. Ideal for high-throughput applications requiring concurrent HTTP requests with controlled resource usage.

#### 🎯 **Core Features**
- **Thread-Safe Pooling** — Multiple threads can safely acquire and return clients
- **RAII Resource Management** — Clients automatically return to pool when out of scope
- **Blocking & Non-Blocking Modes** — get(), tryGet(), and timeout-based acquisition
- **Bounded Resource Control** — Configurable pool size prevents resource exhaustion
- **Automatic Backpressure** — Pool exhaustion provides natural flow control
- **Zero Configuration Overhead** — Pre-populated pool ready on construction
- **Statistics & Monitoring** — Real-time pool utilization and availability metrics
- **Graceful Shutdown** — Clean teardown with client return tracking

#### 📊 **Configuration Options**

```cpp
iora::network::HttpClientPool::Config config;

// Pool sizing
config.poolSize = 20;                                  // Number of clients in pool

// HTTP client settings (applied to all clients)
config.requestTimeout = std::chrono::seconds(30);      // Request timeout
config.connectionTimeout = std::chrono::seconds(10);   // Connection timeout
config.enableKeepAlive = true;                         // HTTP keep-alive
config.followRedirects = true;                         // Follow redirects
config.maxRedirects = 5;                               // Max redirect hops
config.userAgent = "MyApp/2.0";                        // User agent string

// Optional TLS configuration (applied to all clients)
iora::network::HttpClient::TlsConfig tlsConfig;
tlsConfig.caFile = "/path/to/ca-cert.pem";
tlsConfig.verifyPeer = true;
config.tlsConfig = tlsConfig;

// Custom client factory (optional)
config.clientFactory = []() {
    return std::make_unique<iora::network::HttpClient>();
};

// Custom client configurer (optional)
config.clientConfigurer = [](iora::network::HttpClient& client) {
    // Additional per-client configuration
};

auto pool = iora::network::HttpClientPool(config);
```

#### 🚀 **Usage Examples**

**Basic Usage with Automatic Return:**
```cpp
#include "iora/network/http_client_pool.hpp"

// Create pool with 10 clients
iora::network::HttpClientPool::Config config;
config.poolSize = 10;
config.requestTimeout = std::chrono::seconds(30);

iora::network::HttpClientPool pool(config);

// Get client, use it, automatically returns on scope exit
{
    auto client = pool.get();
    auto response = client.get("https://api.example.com/users");

    if (response.success()) {
        std::cout << "Users: " << response.body << std::endl;
    }
}  // Client automatically returned to pool here

// Pool statistics
std::cout << "Pool capacity: " << pool.capacity() << std::endl;
std::cout << "Clients available: " << pool.available() << std::endl;
std::cout << "Clients in use: " << pool.inUse() << std::endl;
std::cout << "Utilization: " << pool.utilization() << "%" << std::endl;
```

**Non-Blocking Acquisition with Backpressure:**
```cpp
// Try to get client without blocking
if (auto client = pool.tryGet()) {
    auto response = client->post("https://api.example.com/events", eventData);
} else {
    // Pool exhausted - apply backpressure
    std::cerr << "Pool exhausted, dropping request" << std::endl;
    metrics.incrementDropped();
}
```

**Timeout-Based Acquisition:**
```cpp
// Wait up to 5 seconds for available client
if (auto client = pool.get(std::chrono::seconds(5))) {
    auto response = client->postJson("https://api.example.com/data", jsonPayload);
    processResponse(response);
} else {
    // Timeout - no client available within 5 seconds
    std::cerr << "Timeout acquiring HTTP client from pool" << std::endl;
}
```

**Multi-Threaded Usage:**
```cpp
// Multiple worker threads sharing the same pool
std::vector<std::thread> workers;

for (int i = 0; i < 20; ++i) {
    workers.emplace_back([&pool, i]() {
        // Each thread acquires clients from shared pool
        for (int j = 0; j < 100; ++j) {
            auto client = pool.get();  // Blocks until client available

            auto response = client.get("https://api.example.com/endpoint/" +
                                      std::to_string(i * 100 + j));

            if (response.success()) {
                processData(response.body);
            }
        }  // Client returned automatically
    });
}

for (auto& t : workers) {
    t.join();
}

// All clients returned to pool
assert(pool.available() == pool.capacity());
```

**Multiple Requests with Same Client:**
```cpp
auto client = pool.get();

// Perform multiple requests with same connection (keep-alive)
auto users = client.get("https://api.example.com/users");
auto posts = client.get("https://api.example.com/posts");
auto comments = client.get("https://api.example.com/comments");

// Process all responses
processUsers(users.body);
processPosts(posts.body);
processComments(comments.body);

// Client returned on scope exit
```

**Integration with ThreadPool:**
```cpp
// Dispatch HTTP requests to thread pool, managed by client pool
iora::network::HttpClientPool clientPool(poolConfig);
iora::core::ThreadPool threadPool(8, 16);

for (const auto& url : urls) {
    threadPool.enqueue([&clientPool, url]() {
        auto client = clientPool.get();
        auto response = client.get(url);
        processResponse(response);
        // Client automatically returned when lambda completes
    });
}
```

**Graceful Shutdown:**
```cpp
// Signal shutdown
clientPool.close();

// Existing PooledHttpClient instances can still be used
// New acquisitions will fail

// Wait for in-flight requests to complete
while (clientPool.inUse() > 0) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

std::cout << "All clients returned, safe to shutdown" << std::endl;
```

#### 🔧 **Advanced Features**

**Pool Monitoring:**
```cpp
void monitorPool(const iora::network::HttpClientPool& pool) {
    std::cout << "=== HTTP Client Pool Status ===" << std::endl;
    std::cout << "Capacity: " << pool.capacity() << std::endl;
    std::cout << "Available: " << pool.available() << std::endl;
    std::cout << "In Use: " << pool.inUse() << std::endl;
    std::cout << "Utilization: " << std::fixed << std::setprecision(1)
              << pool.utilization() << "%" << std::endl;
    std::cout << "Empty: " << (pool.empty() ? "yes" : "no") << std::endl;
    std::cout << "Full: " << (pool.full() ? "yes" : "no") << std::endl;
}

// Call periodically for observability
std::thread monitor([&pool]() {
    while (!shutdown) {
        monitorPool(pool);
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
});
```

**RAII Semantics:**
```cpp
// PooledHttpClient is move-only
auto client1 = pool.get();
auto client2 = std::move(client1);  // Transfer ownership

// client1 is now invalid
assert(!client1.isValid());
assert(client2.isValid());

// client2 will return to pool on destruction
```

**Custom Headers and Configuration:**
```cpp
iora::network::HttpClientPool::Config config;
config.poolSize = 5;

// Default headers applied to all pool clients
config.defaultHeaders = {
    {"Authorization", "Bearer token123"},
    {"X-API-Version", "v2"},
    {"Accept", "application/json"}
};

iora::network::HttpClientPool pool(config);

auto client = pool.get();
// All requests inherit default headers
auto response = client.get("https://api.example.com/data");
```

#### ⚠️ **Best Practices**

✅ **DO:**
- Size pool based on expected concurrent request load
- Use `tryGet()` for backpressure-sensitive applications
- Monitor pool utilization to detect bottlenecks
- Keep acquired clients in tight scopes for quick return
- Use timeout-based acquisition for bounded wait times

❌ **DON'T:**
- Hold clients longer than necessary (blocks other threads)
- Ignore `nullopt` returns from `tryGet()` or timeout-based `get()`
- Access moved-from `PooledHttpClient` instances
- Create pool with size 0 (throws `std::invalid_argument`)
- Perform long-running operations while holding a client

#### 📈 **Performance Characteristics**

- **Zero Allocation After Construction** — All clients pre-created
- **Lock-Free Statistics** — Atomic counters for metrics
- **Bounded Blocking** — Pool exhaustion provides natural backpressure
- **Thread-Safe** — Lock-based synchronization via `BlockingQueue`
- **Connection Reuse** — Keep-alive enabled by default
- **Efficient Wake-up** — Condition variables for blocked threads

### WebhookServer - Production HTTP Server

The `WebhookServer` provides a lightweight, production-ready HTTP server optimized for webhook handling and JSON APIs.

#### 🎯 **Core Features**
- **JSON-First Design** — Built-in JSON request/response handling
- **TLS/HTTPS Support** — Full SSL/TLS encryption with certificate management
- **Thread Pool Architecture** — Efficient request handling with configurable thread pools
- **Graceful Shutdown** — Proper cleanup and connection termination
- **Request Routing** — Path-based routing with parameter extraction
- **Security Features** — Request size limits and parsing controls
- **Production Ready** — Comprehensive error handling and logging

#### 🔧 **Server Configuration**

```cpp
auto& service = iora::IoraService::instanceRef();
auto& server = *service.webhookServer();

// Basic server setup
server.setPort(8080);

// Configure JSON parsing limits
iora::network::WebhookServer::JsonConfig jsonConfig;
jsonConfig.maxPayloadSize = 10 * 1024 * 1024;  // 10MB max payload
jsonConfig.parseLimits.maxDepth = 32;          // Maximum JSON nesting
server.setJsonConfig(jsonConfig);

// Enable TLS/HTTPS
iora::network::WebhookServer::TlsConfig tlsConfig;
tlsConfig.certFile = "/path/to/server-cert.pem";
tlsConfig.keyFile = "/path/to/server-key.pem";
tlsConfig.requireClientCert = false;  // Optional client certificates
server.enableTls(tlsConfig);
```

#### 🚀 **Usage Examples**

**JSON API Endpoints:**
```cpp
#include "iora/iora.hpp"

auto& service = iora::IoraService::instanceRef();

// Register JSON endpoints using fluent API
service.on("/api/users")
    .handleJson([](const iora::parsers::Json& request) -> iora::parsers::Json {
        // Handle user creation
        std::string name = request["name"].get<std::string>();
        std::string email = request["email"].get<std::string>();
        
        // Process user registration...
        
        return iora::parsers::Json::object({
            {"status", "success"},
            {"userId", 12345},
            {"message", "User created successfully"}
        });
    });

service.on("/api/users/{id}")
    .handleJson([](const iora::parsers::Json& request) -> iora::parsers::Json {
        // Handle user lookup by ID
        // ID is available in request parameters
        return iora::parsers::Json::object({
            {"userId", 123},
            {"name", "John Doe"},
            {"email", "john@example.com"}
        });
    });
```

**Traditional HTTP Handlers:**
```cpp
auto& server = *service.webhookServer();

// GET endpoint with custom response
server.onGet("/health", [](const auto& req, auto& res) {
    res.set_content("OK", "text/plain");
    res.status = 200;
});

// POST endpoint with form data
server.onPost("/webhook", [](const auto& req, auto& res) {
    std::cout << "Received webhook: " << req.body << std::endl;
    
    // Access headers
    std::string contentType = req.get_header_value("Content-Type");
    
    // Set response
    res.set_content("{\"received\": true}", "application/json");
    res.status = 200;
});

// DELETE endpoint
server.onDelete("/api/users/{id}", [](const auto& req, auto& res) {
    // Handle user deletion
    res.status = 204; // No Content
});
```

**Advanced Error Handling:**
```cpp
service.on("/api/process")
    .handleJson([&server](const iora::parsers::Json& request) -> iora::parsers::Json {
        auto shutdownChecker = server.getShutdownChecker();
        
        // Long-running operation with shutdown awareness
        while (processingWork()) {
            if (shutdownChecker.isShuttingDown()) {
                throw std::runtime_error("Server is shutting down");
            }
            // Continue processing...
        }
        
        return iora::parsers::Json::object({{"result", "completed"}});
    });
```

### Configuration & TLS Support

#### 🔐 **TLS/HTTPS Configuration**

Both HttpClient and WebhookServer support comprehensive TLS configuration:

**Client TLS Configuration:**
```cpp
iora::network::HttpClient::TlsConfig clientTls;
clientTls.caFile = "/etc/ssl/certs/ca-bundle.pem";     // CA certificate bundle
clientTls.clientCertFile = "/etc/ssl/client.pem";      // Client certificate (optional)
clientTls.clientKeyFile = "/etc/ssl/client-key.pem";   // Client private key (optional)
clientTls.verifyPeer = true;                           // Verify server certificate

client.setTlsConfig(clientTls);
```

**Server TLS Configuration:**
```cpp
iora::network::WebhookServer::TlsConfig serverTls;
serverTls.certFile = "/etc/ssl/server-cert.pem";       // Server certificate
serverTls.keyFile = "/etc/ssl/server-key.pem";         // Server private key
serverTls.caFile = "/etc/ssl/ca-cert.pem";             // CA for client verification (optional)
serverTls.requireClientCert = false;                   // Require client certificates

server.enableTls(serverTls);
```

#### ⚙️ **Production Deployment**

**IoraService Integration:**
```cpp
// Initialize Iora service with HTTP configuration
iora::IoraService::Config config;
config.server.port = 8443;                             // HTTPS port
config.server.tls.certFile = "/etc/ssl/server.pem";
config.server.tls.keyFile = "/etc/ssl/server-key.pem";

iora::IoraService::init(config);

// Server is automatically configured and started
auto& service = iora::IoraService::instanceRef();

// Register your endpoints
service.on("/api/webhook").handleJson(yourHandler);

// Service handles server lifecycle automatically
```

#### 🔧 **Performance Tuning**

```cpp
// Optimize HTTP client for high-throughput scenarios
iora::network::HttpClient::Config highPerfConfig;
highPerfConfig.connectTimeout = std::chrono::milliseconds(500);    // Fast connects
highPerfConfig.requestTimeout = std::chrono::milliseconds(2000);   // Quick requests
highPerfConfig.reuseConnections = true;                            // Essential for performance
highPerfConfig.connectionIdleTimeout = std::chrono::seconds(60);   // Keep connections alive

// Optimize JSON parsing for large payloads
highPerfConfig.jsonConfig.maxPayloadSize = 100 * 1024 * 1024;     // 100MB max
highPerfConfig.jsonConfig.parseLimits.maxDepth = 16;              // Reasonable nesting

auto client = iora::network::HttpClient(highPerfConfig);
```

### Usage Examples

#### 🔄 **Complete Webhook Processing Pipeline**

```cpp
#include "iora/iora.hpp"

class WebhookProcessor {
private:
    iora::network::HttpClient httpClient_;
    
public:
    void setupEndpoints() {
        auto& service = iora::IoraService::instanceRef();
        
        // Receive webhook, process, and forward
        service.on("/webhook/github")
            .handleJson([this](const iora::parsers::Json& payload) -> iora::parsers::Json {
                try {
                    // Validate webhook signature (production requirement)
                    if (!validateSignature(payload)) {
                        throw std::runtime_error("Invalid signature");
                    }
                    
                    // Process the webhook
                    processGitHubEvent(payload);
                    
                    // Forward to downstream services
                    forwardToServices(payload);
                    
                    return iora::parsers::Json::object({
                        {"status", "processed"},
                        {"timestamp", getCurrentTimestamp()}
                    });
                } catch (const std::exception& e) {
                    IORA_LOG_ERROR("Webhook processing failed: " << e.what());
                    throw; // Will return 500 error automatically
                }
            });
    }
    
private:
    void forwardToServices(const iora::parsers::Json& payload) {
        // Forward to multiple downstream services
        std::vector<std::string> endpoints = {
            "https://service1.internal/webhook",
            "https://service2.internal/webhook"
        };
        
        for (const auto& endpoint : endpoints) {
            try {
                auto response = httpClient_.postJson(endpoint, payload, {
                    {"Content-Type", "application/json"},
                    {"X-Forwarded-From", "iora-webhook-processor"}
                }, 2); // 2 retries
                
                if (!response.success()) {
                    IORA_LOG_WARN("Failed to forward to " << endpoint 
                                 << ": " << response.statusCode);
                }
            } catch (const std::exception& e) {
                IORA_LOG_ERROR("Forward error to " << endpoint << ": " << e.what());
            }
        }
    }
};
```

#### 🔄 **HTTP Client with Circuit Breaker**

```cpp
#include "iora/iora.hpp"

class ResilientApiClient {
private:
    iora::network::HttpClient client_;
    iora::util::CircuitBreaker circuitBreaker_;
    
public:
    ResilientApiClient() 
        : circuitBreaker_("external-api", 5, std::chrono::minutes(1)) {
        
        // Configure client for resilience
        iora::network::HttpClient::Config config;
        config.requestTimeout = std::chrono::milliseconds(3000);
        config.maxRedirects = 3;
        config.reuseConnections = true;
        
        client_ = iora::network::HttpClient(config);
    }
    
    iora::parsers::Json fetchUserData(const std::string& userId) {
        return circuitBreaker_.execute<iora::parsers::Json>([&]() {
            auto response = client_.get(
                "https://api.external.com/users/" + userId,
                {{"Authorization", "Bearer " + getApiToken()}},
                2  // 2 retries
            );
            
            if (!response.success()) {
                throw std::runtime_error("API request failed: " + 
                                       std::to_string(response.statusCode));
            }
            
            return iora::parsers::Json::parse(response.body);
        });
    }
};
```

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

### Test Organization

Tests are organized by namespace into logical groups that mirror the `include/iora/` directory structure:

- **NETWORK**: Transport, DNS, HTTP, WebSocket (13 tests)
- **CORE**: Logging, threading, timers (6 tests) 
- **PARSERS**: JSON and XML parsing (2 tests)
- **SERVICE**: Plugin system and main framework (4 tests)
- **STORAGE**: Persistent storage (1 test)
- **UTIL**: Caching and utilities (1 test)
- **DEBUG**: Debug and helper tests (2 tests)

### Selective Test Compilation

By default, no tests are built to speed up compilation. Enable specific test groups using CMake options:

```bash
# Build only network tests
cmake -S . -B build -DIORA_BUILD_NETWORK_TESTS=ON
cmake --build build

# Build only core tests  
cmake -S . -B build -DIORA_BUILD_CORE_TESTS=ON
cmake --build build

# Build all test groups
cmake -S . -B build -DIORA_BUILD_ALL_TESTS=ON
cmake --build build
```

Available test group options:
- `IORA_BUILD_NETWORK_TESTS` - Transport and networking tests
- `IORA_BUILD_CORE_TESTS` - Core functionality tests
- `IORA_BUILD_PARSERS_TESTS` - JSON/XML parser tests
- `IORA_BUILD_SERVICE_TESTS` - Plugin system tests
- `IORA_BUILD_STORAGE_TESTS` - Persistent storage tests
- `IORA_BUILD_UTIL_TESTS` - Utility tests
- `IORA_BUILD_DEBUG_TESTS` - Debug helper tests
- `IORA_BUILD_ALL_TESTS` - Enable all test groups

### Running Tests

Use CTest to run the compiled tests:

```bash
# Run all built tests
ctest --test-dir build

# Run specific test namespace
ctest --test-dir build -R "network::"
ctest --test-dir build -R "core::"
ctest --test-dir build -R "parsers::"

# Run with verbose output
ctest --test-dir build --verbose

# Run specific test by name
ctest --test-dir build -R "iora_test_shared_udp"
```

Alternatively, use the namespace-specific make targets:

```bash
# Run all network tests
make test_network

# Run all core tests  
make test_core

# Run all parsers tests
make test_parsers
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
3. **Dynamic Loading**: Plugins are loaded from a specified directory at runtime. The directory can be configured via the configuration file.

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

### Plugin Dependency System

Iora provides a sophisticated dependency management system that ensures plugins are loaded in the correct order and are notified when their dependencies become available or unavailable.

#### Declaring Dependencies

Plugins can declare dependencies on other plugins using the `require()` method in their `onLoad()` function:

```cpp
class DependentPlugin : public iora::IoraService::Plugin
{
public:
  explicit DependentPlugin(iora::IoraService* service) : Plugin(service) {}

  void onLoad(iora::IoraService* service) override
  {
    // Require that BasePlugin is loaded first
    require("baseplugin.so");
    
    // Export APIs and initialization logic
  }

  void onUnload() override
  {
    // Cleanup logic
  }
};
```

#### Dependency Loading Behavior

- **Automatic Validation**: When a plugin calls `require()`, the system checks if the required plugin is already loaded
- **Strict Enforcement**: If a required dependency is not loaded, the plugin load will fail with a descriptive error
- **Load Order**: Dependencies must be loaded **before** the plugins that require them
- **Manual Loading**: The system does **not** automatically load dependencies - they must be explicitly loaded via TOML configuration in the correct order

#### Dependency Notifications

Plugins can receive notifications when their dependencies are loaded or unloaded by implementing these optional callback methods:

```cpp
class DependentPlugin : public iora::IoraService::Plugin
{
public:
  void onDependencyLoaded(const std::string& moduleName) override
  {
    if (moduleName == "baseplugin.so") {
      // React to dependency becoming available
      _basePluginAvailable = true;
    }
  }

  void onDependencyUnloaded(const std::string& moduleName) override
  {
    if (moduleName == "baseplugin.so") {
      // React to dependency becoming unavailable
      _basePluginAvailable = false;
    }
  }

private:
  bool _basePluginAvailable = false;
};
```

#### Thread-Safe Dependency Tracking

The dependency system is fully thread-safe and handles:

- **Concurrent API Access**: Multiple threads can safely call plugin APIs while modules are being loaded/unloaded
- **Dependency Notifications**: All dependent plugins receive notifications when their dependencies change state
- **Graceful Cleanup**: When a plugin is unloaded, all dependent plugins are notified before the unload completes

#### Best Practices

1. **Declare All Dependencies**: Always call `require()` for every plugin your plugin depends on
2. **Handle Unavailable Dependencies**: Use `onDependencyUnloaded()` to gracefully handle when dependencies become unavailable
3. **Load Order in Configuration**: Ensure your TOML configuration loads plugins in dependency order:

```toml
[modules]
directory = "/path/to/plugins"
modules = [
    "baseplugin.so",      # Load foundation plugins first
    "dependentplugin.so", # Then plugins that depend on them
    "chainedplugin.so"    # Finally plugins with chained dependencies
]
```

4. **Error Handling**: Implement proper error handling for dependency failures:

```cpp
void onLoad(iora::IoraService* service) override
{
  try {
    require("criticalservice.so");
  } catch (const std::runtime_error& e) {
    IORA_LOG_ERROR("Failed to load critical dependency: " + std::string(e.what()));
    throw; // Re-throw to fail plugin load
  }
}
```

### Configuration

To enable plugin loading, specify the directory containing your plugins in your configuration:

- **Configuration File**: Add the following to your TOML configuration:
  ```toml
  [modules]
  directory = "/path/to/plugins"
  modules = [
    "baseplugin.so",
    "dependentplugin.so"
  ]
  ```

### Logging and Error Handling

- Plugin initialization errors are logged using the `iora::core::Logger`.
- Dependency failures result in detailed error messages indicating which dependencies are missing.
- If a plugin fails to load, it will be skipped, and the system will continue loading other plugins.

### JSON-RPC Server Module

The JSON-RPC Server module provides a JSON-RPC 2.0 compliant server that can be dynamically loaded as a plugin. It exposes the following API methods via `IoraService::exportApi`:

#### API Methods

- `jsonrpc.version()` → `std::uint32_t` - Returns the JSON-RPC server version
- `jsonrpc.register(methodName, handler)` → `void` - Registers a method handler
  - `methodName`: `const std::string&` - Name of the JSON-RPC method
  - `handler`: `std::function<iora::parsers::Json(const iora::parsers::Json&)>` - Handler function that takes JSON params and returns JSON result
- `jsonrpc.registerWithOptions(methodName, handler, options)` → `void` - Registers a method handler with options
  - `methodName`: `const std::string&` - Name of the JSON-RPC method  
  - `handler`: `std::function<iora::parsers::Json(const iora::parsers::Json&)>` - Handler function
  - `options`: `const iora::parsers::Json&` - Options object with optional fields:
    - `requireAuth`: `bool` - Whether authentication is required
    - `timeout`: `int` - Timeout in milliseconds  
    - `maxRequestSize`: `int` - Maximum request size in bytes
- `jsonrpc.unregister(methodName)` → `bool` - Unregisters a method
- `jsonrpc.has(methodName)` → `bool` - Checks if a method is registered
- `jsonrpc.getMethods()` → `std::vector<std::string>` - Returns list of registered method names
- `jsonrpc.getStats()` → `iora::parsers::Json` - Returns server statistics as JSON object with fields:
  - `totalRequests`: Total number of requests processed
  - `successfulRequests`: Number of successful requests
  - `failedRequests`: Number of failed requests
  - `timeoutRequests`: Number of timed out requests
  - `batchRequests`: Number of batch requests
  - `notificationRequests`: Number of notification requests
- `jsonrpc.resetStats()` → `void` - Resets all statistics counters

#### Usage Example

```cpp
// Initialize IoraService with configuration
iora::IoraService::Config config;
config.server.port = 8080;
config.modules.directory = "/path/to/plugins";
config.modules.autoLoad = false;
iora::IoraService::init(config);

// Get service instance and load the JSON-RPC server module
auto& service = iora::IoraService::instanceRef();
service.loadSingleModule("/path/to/mod_jsonrpc_server.so");

// Register a simple echo method
auto echoHandler = [](const iora::parsers::Json& params) -> iora::parsers::Json {
    return params; // Echo back the parameters
};
service.callExportedApi<void, const std::string&, std::function<iora::parsers::Json(const iora::parsers::Json&)>>(
    "jsonrpc.register", "echo", echoHandler);

// Register a method with options
auto authHandler = [](const iora::parsers::Json& params) -> iora::parsers::Json {
    return iora::parsers::Json::object({{"authenticated", true}});
};
iora::parsers::Json options = iora::parsers::Json::object();
options["requireAuth"] = true;
options["timeout"] = 5000;
service.callExportedApi<void, const std::string&, std::function<iora::parsers::Json(const iora::parsers::Json&)>, const iora::parsers::Json&>(
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
**Memory Safety**: ✅ **Memory-safe** - uses shared_ptr and weak_ptr to prevent dangling pointers  
**Best for**: Multi-threaded high-frequency API calls

```cpp
// Get thread-safe wrapper (recommended for most use cases)
auto safeAddApi = service.getExportedApiSafe<int(int, int)>("plugin.add");

// Safe to call from multiple threads concurrently
int result = (*safeAddApi)(10, 20); // ~25ns overhead

// Check availability
if (safeAddApi->isAvailable()) {
    result = (*safeAddApi)(5, 7);
}

// Get metadata
std::cout << "Module: " << safeAddApi->getModuleName() << std::endl;
std::cout << "API: " << safeAddApi->getApiName() << std::endl;

// Graceful error handling
try {
    result = (*safeAddApi)(1, 2);
} catch (const std::runtime_error& e) {
    std::cout << "API unavailable: " << e.what() << std::endl;
}

// Store for long-term use - shared_ptr ensures proper cleanup
class MyService {
    std::shared_ptr<iora::IoraService::SafeApiFunction<int(int, int)>> cachedApi_;
    
public:
    MyService(iora::IoraService& service) {
        cachedApi_ = service.getExportedApiSafe<int(int, int)>("plugin.add");
    }
    
    int calculate(int a, int b) {
        return (*cachedApi_)(a, b); // Memory-safe even if module reloads
    }
};
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
int result = (*safeApi)(1, 2);
```

#### Error Handling Patterns

```cpp
// Pattern 1: Exception handling
try {
    auto result = (*safeApi)(10, 20);
    processResult(result);
} catch (const std::runtime_error& e) {
    handleApiUnavailable(e.what());
}

// Pattern 2: Availability checking
if (safeApi->isAvailable()) {
    auto result = (*safeApi)(10, 20);
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
    std::shared_ptr<iora::IoraService::SafeApiFunction<int(int, int)>> cachedAddApi;
    
public:
    MyService(iora::IoraService& service) {
        cachedAddApi = service.getExportedApiSafe<int(int, int)>("plugin.add");
    }
    
    int performCalculation(int a, int b) {
        return (*cachedAddApi)(a, b); // ~25ns overhead, memory-safe
    }
};
```

#### Thread Safety Considerations
```cpp
// Safe: Multiple threads can call concurrently
std::vector<std::thread> workers;
auto safeApi = service.getExportedApiSafe<int(int, int)>("plugin.add");

for (int i = 0; i < 10; ++i) {
    workers.emplace_back([safeApi, i]() {  // Capture shared_ptr by value
        for (int j = 0; j < 1000; ++j) {
            try {
                int result = (*safeApi)(i, j);
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