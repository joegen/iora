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
// Type alias for better readability
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;

// Simple method registration
svc.callExportedApi<void, const std::string&, JsonHandler>(
  "jsonrpc.register", "hello", 
  [](const iora::core::Json& params) -> iora::core::Json
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
| `jsonrpc.register` | `void(const std::string&, std::function<iora::core::Json(const iora::core::Json&)>)` | Register a method handler |
| `jsonrpc.registerWithOptions` | `void(const std::string&, std::function<iora::core::Json(const iora::core::Json&)>, const iora::core::Json&)` | Register method with options (options as JSON) |
| `jsonrpc.unregister` | `bool(const std::string&)` | Unregister a method |
| `jsonrpc.has` | `bool(const std::string&)` | Check if method exists |
| `jsonrpc.getMethods` | `std::vector<std::string>()` | Get list of registered methods |
| `jsonrpc.getStats` | `iora::core::Json()` | Get server statistics as JSON object |
| `jsonrpc.resetStats` | `void()` | Reset server statistics |

### Method Handler Signature

```cpp
// Public method handler signature (used in API calls)
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;
```

Method handlers receive:
- `params`: JSON parameters from the request

Method handlers should:
- Return a JSON result on success
- Throw `std::invalid_argument` for invalid parameters (becomes `-32602` error)
- Throw other exceptions for internal errors (becomes `-32603` error)

**Note**: The internal implementation may use additional context parameters, but the public API only exposes the simplified JSON-to-JSON signature.

### Method Options

Method options are passed as JSON objects with the following structure:

```json
{
  "requireAuth": false,        // Require authentication (default: false)
  "timeout": 5000,            // Request timeout in milliseconds (default: 5000) 
  "maxRequestSize": 1048576   // Max request size in bytes (default: 1MB)
}
```

Example in C++:
```cpp
iora::core::Json options = {
  {"requireAuth", true},
  {"timeout", 10000},
  {"maxRequestSize", 2048576}
};
```

### Request Processing

The server handles request context, authentication, and metadata internally. Method handlers receive only the JSON parameters and return JSON responses. The internal implementation manages:

- **Authentication**: Validated based on method options and HTTP headers
- **Request Metadata**: Timing, client identification, and request size tracking  
- **Service Integration**: Access to IoraService features like state store and logging
- **Error Handling**: Automatic conversion of exceptions to JSON-RPC error responses

This design keeps the public API simple while providing full functionality internally.

## Usage Examples

### Basic Method Registration

```cpp
// Type alias for better readability
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;

// Register a simple echo method
svc.callExportedApi<void, const std::string&, JsonHandler>(
  "jsonrpc.register", "echo",
  [](const iora::core::Json& params) -> iora::core::Json
  {
    return params; // Echo back the parameters
  }
);
```

### Method with Authentication

```cpp
// Type alias for better readability
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;

// Register method that requires authentication
iora::core::Json options = {
  {"requireAuth", true},
  {"timeout", 10000}
};

svc.callExportedApi<void, const std::string&, JsonHandler, const iora::core::Json&>(
  "jsonrpc.registerWithOptions", "secure_method",
  [](const iora::core::Json& params) -> iora::core::Json
  {
    // This handler will only be called if authentication is present
    // Authentication details are handled internally by the server
    return iora::core::Json{
      {"message", "Access granted to secure data"},
      {"data", "sensitive information"},
      {"timestamp", std::time(nullptr)}
    };
  },
  options
);
```

### Method with Custom Options

```cpp
// Type alias for better readability
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;

// Register method with custom timeout and authentication
iora::core::Json options = {
  {"requireAuth", false},
  {"timeout", 15000},        // 15 second timeout for slow operations
  {"maxRequestSize", 2097152} // 2MB max request size
};

svc.callExportedApi<void, const std::string&, JsonHandler, const iora::core::Json&>(
  "jsonrpc.registerWithOptions", "slow_method",
  [](const iora::core::Json& params) -> iora::core::Json
  {
    // Simulate some work - the timeout setting allows for longer processing
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    return iora::core::Json{
      {"status", "completed"},
      {"processing_time", "1000ms"}
    };
  },
  options
);
```

### Calculator Service Example

```cpp
// Type alias for better readability
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;

// Register mathematical operations
svc.callExportedApi<void, const std::string&, JsonHandler>(
  "jsonrpc.register", "add",
  [](const iora::core::Json& params) -> iora::core::Json
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

svc.callExportedApi<void, const std::string&, JsonHandler>(
  "jsonrpc.register", "multiply",
  [](const iora::core::Json& params) -> iora::core::Json
  {
    double a = params.value("a", 1.0);
    double b = params.value("b", 1.0);
    return iora::core::Json{{"result", a * b}};
  }
);
```

### Data Processing Example

```cpp
// Type alias for better readability
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;

// Register data validation method
svc.callExportedApi<void, const std::string&, JsonHandler>(
  "jsonrpc.register", "validate_user",
  [](const iora::core::Json& params) -> iora::core::Json
  {
    // Validate required fields
    if (!params.contains("username") || !params.contains("email"))
    {
      throw std::invalid_argument("Both 'username' and 'email' are required");
    }
    
    std::string username = params["username"].get<std::string>();
    std::string email = params["email"].get<std::string>();
    
    // Perform validation
    bool validUsername = !username.empty() && username.length() >= 3;
    bool validEmail = email.find('@') != std::string::npos;
    
    return iora::core::Json{
      {"valid", validUsername && validEmail},
      {"username_valid", validUsername},
      {"email_valid", validEmail},
      {"timestamp", std::time(nullptr)}
    };
  }
);

// Register data transformation method
svc.callExportedApi<void, const std::string&, JsonHandler>(
  "jsonrpc.register", "format_text",
  [](const iora::core::Json& params) -> iora::core::Json
  {
    std::string text = params.value("text", "");
    std::string format = params.value("format", "upper");
    
    if (text.empty())
    {
      throw std::invalid_argument("Text parameter is required");
    }
    
    std::string result = text;
    if (format == "upper")
    {
      std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    }
    else if (format == "lower")
    {
      std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    }
    
    return iora::core::Json{
      {"original", text},
      {"formatted", result},
      {"format_applied", format}
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
[modules.jsonrpc_server]
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
// Get current statistics as JSON
auto stats = svc.callExportedApi<iora::core::Json>("jsonrpc.getStats");

std::cout << "Total requests: " << stats["totalRequests"] << std::endl;
std::cout << "Successful: " << stats["successfulRequests"] << std::endl;
std::cout << "Failed: " << stats["failedRequests"] << std::endl;
std::cout << "Batch requests: " << stats["batchRequests"] << std::endl;
std::cout << "Notifications: " << stats["notificationRequests"] << std::endl;
std::cout << "Timeout requests: " << stats["timeoutRequests"] << std::endl;

// Reset statistics
svc.callExportedApi<void>("jsonrpc.resetStats");

// Example statistics JSON format:
// {
//   "totalRequests": 1500,
//   "successfulRequests": 1420,
//   "failedRequests": 80,
//   "timeoutRequests": 15,
//   "batchRequests": 25,
//   "notificationRequests": 200
// }
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
2. **Handle Exceptions**: Let exceptions bubble up for proper JSON-RPC error responses  
3. **Return Structured Data**: Use JSON objects for complex return values
4. **Keep Logic Simple**: Method handlers should focus on business logic, not service integration

```cpp
// Type alias for better readability
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;

// Good: Proper validation and error handling
svc.callExportedApi<void, const std::string&, JsonHandler>(
  "jsonrpc.register", "user_validate",
  [](const iora::core::Json& params) -> iora::core::Json
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
    
    // Perform validation logic
    bool usernameValid = username.length() >= 3 && username.length() <= 20;
    bool emailValid = email.length() > 5 && email.find('@') != std::string::npos;
    
    // Return structured result
    return iora::core::Json{
      {"valid", usernameValid && emailValid},
      {"username_valid", usernameValid},
      {"email_valid", emailValid},
      {"timestamp", std::time(nullptr)}
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
[modules.jsonrpc_server]
logRequests = true

[logging]
level = "debug"
```

This will log all incoming requests, responses, and processing details.

## Integration with Client Module

The server module is designed to work seamlessly with the JSON-RPC client module:

```cpp
// Type aliases for better readability
using JsonHandler = std::function<iora::core::Json(const iora::core::Json&)>;
using Headers = std::vector<std::pair<std::string, std::string>>;

// Start server with methods
svc.loadSingleModule("mod_jsonrpc_server.so");
svc.callExportedApi<void, const std::string&, JsonHandler>("jsonrpc.register", "hello", 
  [](const iora::core::Json& params) -> iora::core::Json {
    return iora::core::Json{{"message", "Hello, " + params.value("name", "World") + "!"}};
  });

// Load client and make calls
svc.loadSingleModule("mod_jsonrpc_client.so");
auto result = svc.callExportedApi<iora::core::Json, const std::string&, const std::string&, const iora::core::Json&, const Headers&>(
  "jsonrpc.client.call", "http://localhost:8080/rpc", "hello", 
  iora::core::Json{{"name", "Alice"}}, Headers{});
```

## Wire Protocol Compatibility

The server is fully compatible with the JSON-RPC client module and follows JSON-RPC 2.0 specification:

- **Request Processing**: Proper JSON-RPC 2.0 request validation
- **Parameter Handling**: Correct handling of optional parameters
- **Batch Processing**: Efficient batch request/response handling
- **Notifications**: Proper notification processing (no response)
- **Error Responses**: Standard JSON-RPC error objects

## License

This module is part of the Iora framework and is licensed under the Mozilla Public License 2.0. See the LICENSE file for details.