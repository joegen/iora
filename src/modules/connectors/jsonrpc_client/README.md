# JSON-RPC Client Module

A high-performance JSON-RPC 2.0 client implementation for the Iora microservice framework. This module provides a complete JSON-RPC client with connection pooling, retry logic, batch processing, async operations, and comprehensive error handling.

## Features

- **JSON-RPC 2.0 Compliance**: Full support for JSON-RPC 2.0 specification
- **Connection Pooling**: Per-endpoint connection pooling with configurable limits
- **Batch Processing**: Efficient bulk operations with mixed requests/notifications
- **Retry Logic**: Exponential backoff with configurable retry policies
- **Async Operations**: Non-blocking requests with job tracking
- **Statistics**: Built-in request/response metrics and performance monitoring
- **Thread Safety**: Concurrent request handling with proper synchronization
- **TLS Support**: HTTPS endpoints with configurable TLS options
- **Error Handling**: Comprehensive error reporting with detailed messages
- **Configuration**: TOML-based configuration with runtime overrides
- **Keep-Alive**: HTTP/1.1 connection reuse for better performance
- **Compression**: Optional gzip compression for requests/responses

## Architecture

The module consists of two main components:

1. **`JsonRpcClient`**: Core JSON-RPC client with connection pooling and retry logic
2. **`JsonRpcClientPlugin`**: IoraService plugin that exposes client functionality via API

## Quick Start

### 1. Build and Install

```bash
# Configure and build the project
cmake -S . -B build
cmake --build build --target mod_jsonrpc_client

# The plugin will be installed to /usr/local/lib/iora/modules/
```

### 2. Load the Plugin

```cpp
#include "iora/iora.hpp"

int main()
{
  // Initialize IoraService
  iora::IoraService& svc = iora::IoraService::instance();
  
  // Load the JSON-RPC client plugin
  svc.loadSingleModule("/usr/local/lib/iora/modules/mod_jsonrpc_client.so");
  
  return 0;
}
```

### 3. Make RPC Calls

```cpp
// Simple method call
iora::core::Json params = {{"name", "World"}};
std::vector<std::pair<std::string, std::string>> headers;

auto result = svc.callExportedApi<iora::core::Json, 
  const std::string&, const std::string&, const iora::core::Json&, 
  const std::vector<std::pair<std::string, std::string>>&>(
  "jsonrpc.client.call", "http://api.example.com/rpc", "hello", params, headers);

std::cout << "Response: " << result.dump() << std::endl;
```

## API Reference

### Exported Plugin APIs

The plugin exports the following APIs via `IoraService::callExportedApi`:

| API | Signature | Description |
|-----|-----------|-------------|
| `jsonrpc.client.version` | `std::uint32_t()` | Get plugin version |
| `jsonrpc.client.call` | `iora::core::Json(endpoint, method, params, headers)` | Synchronous RPC call |
| `jsonrpc.client.notify` | `void(endpoint, method, params, headers)` | Send notification (no response) |
| `jsonrpc.client.callBatch` | `std::vector<iora::core::Json>(endpoint, items, headers)` | Batch RPC calls |
| `jsonrpc.client.callAsync` | `std::string(endpoint, method, params, headers)` | Async RPC call (returns job ID) |
| `jsonrpc.client.callBatchAsync` | `std::string(endpoint, items, headers)` | Async batch calls (returns job ID) |
| `jsonrpc.client.result` | `iora::core::Json(jobId)` | Get async operation result |
| `jsonrpc.client.getStats` | `const ClientStats&()` | Get client statistics |
| `jsonrpc.client.resetStats` | `void()` | Reset client statistics |
| `jsonrpc.client.purgeIdle` | `std::size_t()` | Remove idle connections |

### Batch Item Structure

```cpp
// Batch request item
struct BatchItem
{
  std::string method;
  iora::core::Json params;
  std::optional<std::uint64_t> id; // None for notifications
  
  // Constructor for regular request
  BatchItem(std::string method, iora::core::Json params, std::uint64_t id);
  
  // Constructor for notification
  BatchItem(std::string method, iora::core::Json params);
};
```

### Client Statistics

```cpp
struct ClientStats
{
  std::atomic<std::uint64_t> totalRequests;
  std::atomic<std::uint64_t> successfulRequests;
  std::atomic<std::uint64_t> failedRequests;
  std::atomic<std::uint64_t> timeoutRequests;
  std::atomic<std::uint64_t> retriedRequests;
  std::atomic<std::uint64_t> batchRequests;
  std::atomic<std::uint64_t> notificationRequests;
  std::atomic<std::uint64_t> poolExhaustions;
  std::atomic<std::uint64_t> connectionsCreated;
  std::atomic<std::uint64_t> connectionsEvicted;
};
```

## Usage Examples

### Basic RPC Calls

```cpp
// Simple RPC call
iora::core::Json params = {{"message", "Hello, World!"}};
std::vector<std::pair<std::string, std::string>> headers;

auto result = svc.callExportedApi<iora::core::Json, 
  const std::string&, const std::string&, const iora::core::Json&, 
  const std::vector<std::pair<std::string, std::string>>&>(
  "jsonrpc.client.call", "http://localhost:8080/rpc", "echo", params, headers);

std::cout << "Echo result: " << result.dump() << std::endl;
```

### Notifications

```cpp
// Send notification (no response expected)
iora::core::Json params = {{"event", "user_login"}, {"user_id", 12345}};
std::vector<std::pair<std::string, std::string>> headers;

svc.callExportedApi<void, 
  const std::string&, const std::string&, const iora::core::Json&, 
  const std::vector<std::pair<std::string, std::string>>&>(
  "jsonrpc.client.notify", "http://localhost:8080/rpc", "log_event", params, headers);
```

### Batch Processing

```cpp
// Create batch items
std::vector<iora::modules::jsonrpc::BatchItem> items = {
  iora::modules::jsonrpc::BatchItem("add", iora::core::Json{{"a", 1}, {"b", 2}}, 1),
  iora::modules::jsonrpc::BatchItem("multiply", iora::core::Json{{"a", 3}, {"b", 4}}, 2),
  iora::modules::jsonrpc::BatchItem("log_event", iora::core::Json{{"event", "batch_test"}}) // Notification
};

std::vector<std::pair<std::string, std::string>> headers;

auto results = svc.callExportedApi<std::vector<iora::core::Json>, 
  const std::string&, const std::vector<iora::modules::jsonrpc::BatchItem>&, 
  const std::vector<std::pair<std::string, std::string>>&>(
  "jsonrpc.client.callBatch", "http://localhost:8080/rpc", items, headers);

// results[0] = {"result": 3}
// results[1] = {"result": 12} 
// results[2] = null (notification)
```

### Async Operations

```cpp
// Start async operation
iora::core::Json params = {{"url", "https://example.com/data"}};
std::vector<std::pair<std::string, std::string>> headers;

std::string jobId = svc.callExportedApi<std::string, 
  const std::string&, const std::string&, const iora::core::Json&, 
  const std::vector<std::pair<std::string, std::string>>&>(
  "jsonrpc.client.callAsync", "http://localhost:8080/rpc", "fetch_data", params, headers);

// Poll for result
while (true) {
  auto status = svc.callExportedApi<iora::core::Json, const std::string&>(
    "jsonrpc.client.result", jobId);
  
  if (status.value("done", false)) {
    if (status.contains("result")) {
      std::cout << "Success: " << status["result"].dump() << std::endl;
    } else if (status.contains("error")) {
      std::cout << "Error: " << status["error"]["message"] << std::endl;
    }
    break;
  }
  
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
}
```

### Statistics and Monitoring

```cpp
// Get current statistics
const auto& stats = svc.callExportedApi<const iora::modules::jsonrpc::ClientStats&>(
  "jsonrpc.client.getStats");

std::cout << "Total requests: " << stats.totalRequests << std::endl;
std::cout << "Successful: " << stats.successfulRequests << std::endl;
std::cout << "Failed: " << stats.failedRequests << std::endl;
std::cout << "Retried: " << stats.retriedRequests << std::endl;
std::cout << "Batch requests: " << stats.batchRequests << std::endl;
std::cout << "Notifications: " << stats.notificationRequests << std::endl;
std::cout << "Pool exhaustions: " << stats.poolExhaustions << std::endl;
std::cout << "Connections created: " << stats.connectionsCreated << std::endl;
std::cout << "Connections evicted: " << stats.connectionsEvicted << std::endl;

// Reset statistics
svc.callExportedApi<void>("jsonrpc.client.resetStats");

// Purge idle connections
auto evicted = svc.callExportedApi<std::size_t>("jsonrpc.client.purgeIdle");
std::cout << "Evicted " << evicted << " idle connections" << std::endl;
```

### Custom Headers and Authentication

```cpp
// Add custom headers (e.g., for authentication)
std::vector<std::pair<std::string, std::string>> headers = {
  {"Authorization", "Bearer your-token-here"},
  {"X-Client-Version", "1.0.0"}
};

iora::core::Json params = {{"user_id", 12345}};

auto result = svc.callExportedApi<iora::core::Json, 
  const std::string&, const std::string&, const iora::core::Json&, 
  const std::vector<std::pair<std::string, std::string>>&>(
  "jsonrpc.client.call", "https://secure-api.example.com/rpc", "get_user_data", params, headers);
```

### Error Handling

```cpp
try {
  iora::core::Json params = {{"invalid", "params"}};
  std::vector<std::pair<std::string, std::string>> headers;
  
  auto result = svc.callExportedApi<iora::core::Json, 
    const std::string&, const std::string&, const iora::core::Json&, 
    const std::vector<std::pair<std::string, std::string>>&>(
    "jsonrpc.client.call", "http://localhost:8080/rpc", "validate_params", params, headers);
}
catch (const iora::modules::jsonrpc::RemoteError& e) {
  // JSON-RPC protocol error from server
  std::cout << "JSON-RPC error " << e.code() << ": " << e.message() << std::endl;
  if (!e.data().is_null()) {
    std::cout << "Error data: " << e.data().dump() << std::endl;
  }
}
catch (const iora::modules::jsonrpc::PoolExhaustedError& e) {
  // No available connections
  std::cout << "Connection pool exhausted: " << e.what() << std::endl;
}
catch (const iora::modules::jsonrpc::JsonRpcError& e) {
  // General JSON-RPC client error
  std::cout << "JSON-RPC client error: " << e.what() << std::endl;
}
catch (const std::exception& e) {
  // Other errors (network, timeout, etc.)
  std::cout << "Error: " << e.what() << std::endl;
}
```

## Configuration

Configure the JSON-RPC client in your TOML configuration file:

```toml
[iora.modules.jsonrpcClient]
enabled = true
maxConnections = 8                    # Per-endpoint connection limit
globalMaxConnections = 0              # Global limit (0 = unlimited)
maxEndpointPools = 0                  # Max endpoint pools (0 = unlimited)
idleTimeoutMs = 30000                 # Connection idle timeout
requestTimeoutMs = 30000              # Request timeout
connectionTimeoutMs = 10000           # Connection establishment timeout
maxRetries = 3                        # Retry attempts on failure
retryBackoffMultiplier = 2.0          # Exponential backoff multiplier
initialRetryDelayMs = 100             # Initial retry delay
maxRetryDelayMs = 5000                # Maximum retry delay
enableKeepAlive = true                # HTTP keep-alive
enableCompression = true              # Gzip compression
defaultHeaders = "User-Agent:IoraClient,Accept:application/json"

[iora.modules.jsonrpcClient.tls]
verifyPeer = true                     # Verify SSL certificates
caCertPath = "/path/to/ca.pem"        # Custom CA certificate
clientCertPath = "/path/to/client.pem" # Client certificate for mTLS
clientKeyPath = "/path/to/client.key" # Client private key for mTLS
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable the plugin |
| `maxConnections` | int | `8` | Max connections per endpoint |
| `globalMaxConnections` | int | `0` | Global connection limit (0 = unlimited) |
| `maxEndpointPools` | int | `0` | Max endpoint pools (0 = unlimited) |
| `idleTimeoutMs` | int | `30000` | Idle timeout for connections |
| `requestTimeoutMs` | int | `30000` | Individual request timeout |
| `connectionTimeoutMs` | int | `10000` | Connection establishment timeout |
| `maxRetries` | int | `3` | Maximum retry attempts |
| `retryBackoffMultiplier` | double | `2.0` | Exponential backoff multiplier |
| `initialRetryDelayMs` | int | `100` | Initial retry delay |
| `maxRetryDelayMs` | int | `5000` | Maximum retry delay |
| `enableKeepAlive` | bool | `true` | Enable HTTP keep-alive |
| `enableCompression` | bool | `true` | Enable gzip compression |
| `defaultHeaders` | string | - | Default headers (format: "Key:Value,Key2:Value2") |

### TLS Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tls.verifyPeer` | bool | `true` | Verify SSL certificates |
| `tls.caCertPath` | string | - | Path to custom CA certificate |
| `tls.clientCertPath` | string | - | Path to client certificate |
| `tls.clientKeyPath` | string | - | Path to client private key |

## Error Handling

The client provides comprehensive error handling with specific exception types:

### Exception Hierarchy

```cpp
std::runtime_error
└── JsonRpcError                    // Base JSON-RPC client error
    ├── PoolExhaustedError         // Connection pool exhausted
    └── RemoteError               // JSON-RPC error from server
```

### Standard JSON-RPC Errors

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON received |
| -32600 | Invalid Request | Request is not valid JSON-RPC |
| -32601 | Method not found | Method does not exist |
| -32602 | Invalid params | Invalid method parameters |
| -32603 | Internal error | Internal JSON-RPC error |

### Client-Specific Errors

- **Connection Errors**: Network timeouts, DNS failures, connection refused
- **Pool Exhaustion**: No available connections in pool
- **Timeout Errors**: Request timeout exceeded
- **Retry Exhaustion**: Maximum retry attempts exceeded

### Error Response Format

Remote errors preserve the JSON-RPC error structure:

```cpp
try {
  // RPC call that fails
}
catch (const iora::modules::jsonrpc::RemoteError& e) {
  std::cout << "Code: " << e.code() << std::endl;        // -32602
  std::cout << "Message: " << e.message() << std::endl;  // "Invalid params"
  std::cout << "Data: " << e.data().dump() << std::endl; // Additional error data
}
```

## Performance Optimization

### Connection Pooling

The client maintains per-endpoint connection pools to minimize connection overhead:

- **Per-endpoint pools**: Each unique endpoint gets its own pool
- **Connection reuse**: HTTP keep-alive for connection reuse
- **Lazy creation**: Connections created on-demand
- **Idle eviction**: Unused connections automatically cleaned up
- **Global limits**: Optional global connection limits across all endpoints

### Batch Processing

Use batch requests for multiple operations to reduce network overhead:

```cpp
// Instead of multiple single calls:
// call("add", {a:1, b:2})
// call("mul", {a:3, b:4})
// call("div", {a:8, b:2})

// Use batch:
std::vector<BatchItem> items = {
  BatchItem("add", {{"a", 1}, {"b", 2}}, 1),
  BatchItem("mul", {{"a", 3}, {"b", 4}}, 2),
  BatchItem("div", {{"a", 8}, {"b", 2}}, 3)
};
auto results = callBatch(endpoint, items, headers);
```

### Async Operations

Use async calls for non-blocking operations:

```cpp
// Start multiple operations concurrently
std::vector<std::string> jobs;
for (int i = 0; i < 10; ++i) {
  jobs.push_back(callAsync(endpoint, "process", {{"id", i}}, {}));
}

// Collect results
std::vector<iora::core::Json> results;
for (const auto& jobId : jobs) {
  // Poll or wait for completion
  auto result = waitForResult(jobId);
  results.push_back(result);
}
```

### Retry Strategy

The client implements intelligent retry logic:

- **Exponential backoff**: Increasing delays between retries
- **Jitter**: Randomized delays to prevent thundering herd
- **Configurable limits**: Maximum attempts and delays
- **Smart filtering**: Only retries transient errors

## Testing

A full integration test suite is available to verify the JSON-RPC client/server functionality:

### Full Integration Tests (Advanced)

For complete client-server integration tests with a full Iora service setup, see the comprehensive test file `iora/src/modules/connectors/jsonrpc_client/tests/iora_test_mod_jsonrpc_client_server_real.cpp`. These tests require proper service configuration and can be adapted for specific deployment environments.

## Best Practices

### Connection Management

1. **Pool Configuration**: Set appropriate connection limits based on your workload
2. **Idle Cleanup**: Regularly call `purgeIdle()` to clean up unused connections
3. **Global Limits**: Use global limits to prevent resource exhaustion
4. **Monitoring**: Monitor pool statistics for optimization opportunities

### Request Optimization

1. **Batch Operations**: Group related requests into batch calls
2. **Async for Latency**: Use async calls for long-running operations
3. **Proper Timeouts**: Configure timeouts based on expected response times
4. **Retry Strategy**: Tune retry parameters for your network conditions

### Error Handling

1. **Specific Exceptions**: Catch specific exception types for appropriate handling
2. **Retry Logic**: Implement application-level retry for critical operations
3. **Circuit Breaker**: Consider circuit breaker patterns for failing endpoints
4. **Graceful Degradation**: Have fallback strategies for service failures

### Security

1. **TLS Verification**: Always verify certificates in production
2. **Authentication**: Use proper authentication headers
3. **Input Validation**: Validate parameters before sending requests
4. **Error Messages**: Don't expose sensitive information in error handling

## Wire Protocol Compatibility

The client is fully compatible with the JSON-RPC server module and follows JSON-RPC 2.0 specification:

- **Request Format**: Proper JSON-RPC 2.0 request envelopes
- **Parameter Handling**: Correct omission of empty parameters
- **Batch Processing**: Proper batch request/response handling
- **Notifications**: Correct notification format (no ID field)
- **Error Responses**: Proper JSON-RPC error object parsing

## Integration with Server Module

The client module is designed to work seamlessly with the JSON-RPC server module:

```cpp
// Start server
svc.loadSingleModule("mod_jsonrpc_server.so");

// Register methods on server
svc.callExportedApi<void>("jsonrpc.register", "hello", handler);

// Load client  
svc.loadSingleModule("mod_jsonrpc_client.so");

// Make calls to server
auto result = svc.callExportedApi<iora::core::Json>("jsonrpc.client.call", 
  "http://localhost:8080/rpc", "hello", params, headers);
```

## Troubleshooting

### Common Issues

1. **Plugin Not Loading**
   - Verify plugin path exists and is accessible
   - Check library dependencies are available
   - Review logs for detailed error messages

2. **Connection Failures**
   - Verify endpoint URLs are correct
   - Check network connectivity and firewall rules
   - Ensure target server is running and accessible

3. **Timeout Errors**
   - Increase request timeout for slow operations
   - Check network latency and server response times
   - Consider using async calls for long operations

4. **Pool Exhaustion**
   - Increase per-endpoint or global connection limits
   - Implement connection cleanup in your application
   - Monitor connection usage patterns

5. **TLS Errors**
   - Verify certificate paths and permissions
   - Check certificate validity and chain
   - Ensure TLS configuration matches server requirements

### Debug Mode

Enable detailed logging for troubleshooting:

```toml
[logging]
level = "debug"
```

This will log all requests, responses, retry attempts, and connection pool operations.

## License

This module is part of the Iora framework and is licensed under the Mozilla Public License 2.0. See the LICENSE file for details.