# JSON-RPC Server Module

A robust JSON-RPC 2.0 server implementation for the Iora microservice framework. This module provides a complete JSON-RPC server with support for method registration, request validation, batch processing, authentication, and comprehensive error handling.

## Features

- **JSON-RPC 2.0 Compliance**: Full support for JSON-RPC 2.0 specification
- **Method Management**: Dynamic method registration/unregistration with options
- **Batch Processing**: Handle multiple requests in a single HTTP call
- **Authentication Support**: Optional authentication with configurable requirements per method
- **Request Hooks**: Pre and post-processing hooks for methods
- **Statistics**: Built-in request/response metrics and performance monitoring
- **Thread Safety**: Concurrent request handling with proper synchronization
- **Error Handling**: Comprehensive error reporting with detailed messages
- **Configuration**: TOML-based configuration with runtime overrides

## Architecture

The module consists of two main components:

1. **`JsonRpcServer`**: Core JSON-RPC protocol handler and method dispatcher
2. **`JsonRpcServerPlugin`**: IoraService plugin that exposes HTTP endpoint and API

## Quick Start

### 1. Build and Install

```bash
# Configure and build the project
cmake -S . -B build
cmake --build build --target mod_jsonrpc_server

# The plugin will be installed to /usr/local/lib/iora/modules/
```

### 2. Load the Plugin

```cpp
#include "iora/iora.hpp"

int main()
{
  // Initialize IoraService
  iora::IoraService& svc = iora::IoraService::instance();
  
  // Load the JSON-RPC server plugin
  svc.loadSingleModule("/usr/local/lib/iora/modules/mod_jsonrpc_server.so");
  
  return 0;
}
```

### 3. Register Methods

```cpp
// Simple method registration
svc.callExportedApi<void, const std::string&, iora::modules::jsonrpc::MethodHandler>(
  "jsonrpc.register", "hello", 
  [](const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx) -> iora::core::Json
  {
    std::string name = params.value("name", "World");
    return iora::core::Json{{"message", "Hello, " + name + "!"}};
  }
);
```

## API Reference

### Exported Plugin APIs

The plugin exports the following APIs via `IoraService::callExportedApi`:

| API | Signature | Description |
|-----|-----------|-------------|
| `jsonrpc.version` | `std::uint32_t()` | Get plugin version |
| `jsonrpc.register` | `void(const std::string&, MethodHandler)` | Register a method handler |
| `jsonrpc.registerWithOptions` | `void(const std::string&, MethodHandler, MethodOptions)` | Register method with options |
| `jsonrpc.unregister` | `bool(const std::string&)` | Unregister a method |
| `jsonrpc.has` | `bool(const std::string&)` | Check if method exists |
| `jsonrpc.getMethods` | `std::vector<std::string>()` | Get list of registered methods |
| `jsonrpc.getStats` | `const ServerStats&()` | Get server statistics |
| `jsonrpc.resetStats` | `void()` | Reset server statistics |

### Method Handler Signature

```cpp
using MethodHandler = std::function<iora::core::Json(const iora::core::Json&, RpcContext&)>;
```

Method handlers receive:
- `params`: JSON parameters from the request
- `ctx`: Request context with service access and metadata

Method handlers should:
- Return a JSON result on success
- Throw `std::invalid_argument` for invalid parameters (becomes `-32602` error)
- Throw other exceptions for internal errors (becomes `-32603` error)

### Method Options

```cpp
struct MethodOptions
{
  bool requireAuth = false;                       // Require authentication
  std::chrono::milliseconds timeout{5000};       // Request timeout
  std::size_t maxRequestSize = 1024 * 1024;      // Max request size (1MB)
  MethodPreHook preHook;                          // Pre-execution hook
  MethodPostHook postHook;                        // Post-execution hook
};
```

### Request Context

```cpp
class RpcContext
{
public:
  IoraService& service() const;                   // Access to IoraService
  const std::optional<std::string>& authSubject() const; // Authenticated user
  const RequestMetadata& metadata() const;       // Request metadata
};

struct RequestMetadata
{
  std::chrono::steady_clock::time_point startTime; // Request start time
  std::string clientId;                           // Client identifier
  std::string method;                             // Method name
  std::size_t requestSize;                        // Request body size
};
```

## Usage Examples

### Basic Method Registration

```cpp
// Register a simple echo method
svc.callExportedApi<void, const std::string&, iora::modules::jsonrpc::MethodHandler>(
  "jsonrpc.register", "echo",
  [](const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx) -> iora::core::Json
  {
    return params; // Echo back the parameters
  }
);
```

### Method with Authentication

```cpp
// Register method that requires authentication
iora::modules::jsonrpc::MethodOptions opts;
opts.requireAuth = true;

svc.callExportedApi<void, const std::string&, iora::modules::jsonrpc::MethodHandler, const iora::modules::jsonrpc::MethodOptions&>(
  "jsonrpc.registerWithOptions", "secure_method",
  [](const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx) -> iora::core::Json
  {
    // This handler will only be called if authentication is present
    return iora::core::Json{
      {"user", ctx.authSubject().value()},
      {"data", "sensitive information"}
    };
  },
  opts
);
```

### Method with Hooks

```cpp
iora::modules::jsonrpc::MethodOptions opts;

// Pre-execution hook for logging
opts.preHook = [](const std::string& method, const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx)
{
  ctx.service().logger().info("Executing method: {} with {} parameters", method, params.size());
};

// Post-execution hook for metrics
opts.postHook = [](const std::string& method, const iora::core::Json& params, 
                  const iora::core::Json& result, iora::modules::jsonrpc::RpcContext& ctx)
{
  auto duration = std::chrono::steady_clock::now() - ctx.metadata().startTime;
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
  ctx.service().logger().debug("Method {} completed in {}ms", method, ms.count());
};

svc.callExportedApi<void, const std::string&, iora::modules::jsonrpc::MethodHandler, const iora::modules::jsonrpc::MethodOptions&>(
  "jsonrpc.registerWithOptions", "monitored_method",
  [](const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx) -> iora::core::Json
  {
    // Simulate some work
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return iora::core::Json{{"status", "completed"}};
  },
  opts
);
```

### Calculator Service Example

```cpp
// Register mathematical operations
svc.callExportedApi<void, const std::string&, iora::modules::jsonrpc::MethodHandler>(
  "jsonrpc.register", "add",
  [](const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx) -> iora::core::Json
  {
    if (!params.contains("a") || !params.contains("b"))
    {
      throw std::invalid_argument("Parameters 'a' and 'b' are required");
    }
    
    double a = params["a"].get<double>();
    double b = params["b"].get<double>();
    return iora::core::Json{{"result", a + b}};
  }
);

svc.callExportedApi<void, const std::string&, iora::modules::jsonrpc::MethodHandler>(
  "jsonrpc.register", "multiply",
  [](const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx) -> iora::core::Json
  {
    double a = params.value("a", 1.0);
    double b = params.value("b", 1.0);
    return iora::core::Json{{"result", a * b}};
  }
);
```

### File Operations with Service Integration

```cpp
// Register file operations that use IoraService features
svc.callExportedApi<void, const std::string&, iora::modules::jsonrpc::MethodHandler>(
  "jsonrpc.register", "save_data",
  [](const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx) -> iora::core::Json
  {
    std::string key = params.value("key", "");
    if (key.empty())
    {
      throw std::invalid_argument("Key parameter is required");
    }
    
    // Use IoraService state store
    ctx.service().stateStore().set(key, params["data"]);
    
    return iora::core::Json{
      {"success", true},
      {"key", key},
      {"timestamp", std::time(nullptr)}
    };
  }
);

svc.callExportedApi<void, const std::string&, iora::modules::jsonrpc::MethodHandler>(
  "jsonrpc.register", "load_data",
  [](const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx) -> iora::core::Json
  {
    std::string key = params.value("key", "");
    if (key.empty())
    {
      throw std::invalid_argument("Key parameter is required");
    }
    
    auto data = ctx.service().stateStore().get(key);
    if (!data.has_value())
    {
      return iora::core::Json{{"found", false}};
    }
    
    return iora::core::Json{
      {"found", true},
      {"data", data.value()}
    };
  }
);
```

## HTTP Client Usage

Once methods are registered, they can be called via HTTP POST requests to the configured endpoint (default: `/rpc`):

### Single Request

```bash
curl -X POST http://localhost:8080/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "add",
    "params": {"a": 5, "b": 3},
    "id": 1
  }'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {"result": 8},
  "id": 1
}
```

### Batch Request

```bash
curl -X POST http://localhost:8080/rpc \
  -H "Content-Type: application/json" \
  -d '[
    {"jsonrpc": "2.0", "method": "add", "params": {"a": 1, "b": 2}, "id": 1},
    {"jsonrpc": "2.0", "method": "multiply", "params": {"a": 3, "b": 4}, "id": 2}
  ]'
```

Response:
```json
[
  {"jsonrpc": "2.0", "result": {"result": 3}, "id": 1},
  {"jsonrpc": "2.0", "result": {"result": 12}, "id": 2}
]
```

### Notification (No Response)

```bash
curl -X POST http://localhost:8080/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "log_event",
    "params": {"event": "user_login", "user": "alice"}
  }'
```

## Configuration

Configure the JSON-RPC server in your TOML configuration file:

```toml
[modules.jsonrpc]
enabled = true
path = "/rpc"                    # HTTP endpoint path
maxRequestBytes = 1048576        # Max request size (1MB)
maxBatchItems = 50               # Max items in batch request
requireAuth = false              # Global auth requirement
timeoutMs = 5000                 # Request timeout
logRequests = false              # Log all requests
enableMetrics = true             # Enable statistics
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable/disable the plugin |
| `path` | string | `"/rpc"` | HTTP endpoint path |
| `maxRequestBytes` | int | `1048576` | Maximum request body size |
| `maxBatchItems` | int | `50` | Maximum batch request items |
| `requireAuth` | bool | `false` | Require authentication for all methods |
| `timeoutMs` | int | `5000` | Request timeout in milliseconds |
| `logRequests` | bool | `false` | Log all incoming requests |
| `enableMetrics` | bool | `true` | Enable statistics collection |

## Error Handling

The server returns JSON-RPC 2.0 compliant error responses:

### Standard Errors

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON received |
| -32600 | Invalid Request | Request is not valid JSON-RPC |
| -32601 | Method not found | Method does not exist |
| -32602 | Invalid params | Invalid method parameters |
| -32603 | Internal error | Internal JSON-RPC error |

### Custom Errors

| Code | Message | Description |
|------|---------|-------------|
| -32000 | Timeout error | Request timeout exceeded |
| -32001 | Authentication error | Authentication required |
| -32002 | Rate limit exceeded | Too many requests |

### Error Response Format

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params: Parameter 'name' is required",
    "data": {
      "received_params": {...},
      "expected_format": {...}
    }
  },
  "id": 1
}
```

## Monitoring and Statistics

Access server statistics through the plugin API:

```cpp
// Get current statistics
const auto& stats = svc.callExportedApi<const iora::modules::jsonrpc::ServerStats&>("jsonrpc.getStats");

std::cout << "Total requests: " << stats.totalRequests << std::endl;
std::cout << "Successful: " << stats.successfulRequests << std::endl;
std::cout << "Failed: " << stats.failedRequests << std::endl;
std::cout << "Batch requests: " << stats.batchRequests << std::endl;
std::cout << "Notifications: " << stats.notificationRequests << std::endl;

// Reset statistics
svc.callExportedApi<void>("jsonrpc.resetStats");
```

## Testing

Run the comprehensive test suite:

```bash
# Build and run tests
cmake --build build --target iora_test_mod_jsonrpc_server
./build/src/modules/endpoints/jsonrpc_server/tests/iora_test_mod_jsonrpc_server

# Run specific test categories
./build/src/modules/endpoints/jsonrpc_server/tests/iora_test_mod_jsonrpc_server [basic]
./build/src/modules/endpoints/jsonrpc_server/tests/iora_test_mod_jsonrpc_server [batch]
./build/src/modules/endpoints/jsonrpc_server/tests/iora_test_mod_jsonrpc_server [concurrency]
```

Test categories include:
- `[basic]` - Basic functionality tests
- `[validation]` - Request validation tests
- `[batch]` - Batch processing tests
- `[errors]` - Error handling tests
- `[stats]` - Statistics tests
- `[concurrency]` - Thread safety tests
- `[plugin]` - Plugin integration tests

## Best Practices

### Method Implementation

1. **Validate Parameters**: Always validate required parameters and throw `std::invalid_argument` for invalid input
2. **Use Context**: Leverage the `RpcContext` to access IoraService features
3. **Handle Exceptions**: Let exceptions bubble up for proper JSON-RPC error responses
4. **Return Structured Data**: Use JSON objects for complex return values

```cpp
// Good: Proper validation and error handling
svc.callExportedApi<void, const std::string&, iora::modules::jsonrpc::MethodHandler>(
  "jsonrpc.register", "user_create",
  [](const iora::core::Json& params, iora::modules::jsonrpc::RpcContext& ctx) -> iora::core::Json
  {
    // Validate required parameters
    if (!params.contains("username") || !params.contains("email"))
    {
      throw std::invalid_argument("Both 'username' and 'email' are required");
    }
    
    std::string username = params["username"].get<std::string>();
    std::string email = params["email"].get<std::string>();
    
    // Validate format
    if (username.empty() || email.find('@') == std::string::npos)
    {
      throw std::invalid_argument("Invalid username or email format");
    }
    
    // Use service features
    std::string userId = generateUserId();
    ctx.service().stateStore().set("user:" + userId, params);
    
    // Return structured result
    return iora::core::Json{
      {"success", true},
      {"userId", userId},
      {"created", std::time(nullptr)}
    };
  }
);
```

### Security Considerations

1. **Authentication**: Use method options to require authentication for sensitive operations
2. **Input Validation**: Validate all input parameters to prevent injection attacks
3. **Rate Limiting**: Implement application-level rate limiting for public endpoints
4. **Error Messages**: Don't leak sensitive information in error messages

### Performance Optimization

1. **Method Options**: Set appropriate request size limits and timeouts
2. **Batch Processing**: Use batch requests for multiple operations
3. **Async Operations**: For long-running operations, consider returning immediately and using notifications
4. **Caching**: Leverage IoraService features like ExpiringCache for frequently accessed data

## Troubleshooting

### Common Issues

1. **Plugin Not Loading**
   - Verify plugin path exists
   - Check file permissions
   - Review logs for detailed error messages

2. **Methods Not Found**
   - Ensure methods are registered after plugin load
   - Check method names for typos
   - Verify plugin is loaded successfully

3. **Authentication Failures**
   - Check `requireAuth` setting in method options
   - Verify Authorization header format (`Bearer <token>`)
   - Implement proper auth token validation

4. **Request Size Errors**
   - Adjust `maxRequestBytes` in configuration
   - Check `maxRequestSize` in method options
   - Consider streaming for large payloads

### Debug Mode

Enable detailed logging to troubleshoot issues:

```toml
[modules.jsonrpc]
logRequests = true

[logging]
level = "debug"
```

This will log all incoming requests, responses, and processing details.

## License

This module is part of the Iora framework and is licensed under the Mozilla Public License 2.0. See the LICENSE file for details.