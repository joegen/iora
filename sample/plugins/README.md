# Iora Sample Plugins

This directory contains example plugins that demonstrate the **correct** way to extend Iora functionality.

## Microservice Plugin

The `microservice_plugin.cpp` demonstrates how to build a text summarization microservice as an Iora plugin.

### Key Differences from Standalone Applications

**❌ INCORRECT:**
```cpp
// Don't do this - initializing IoraService in your application
auto& svc = iora::IoraService::init(argc, argv);
```

**✅ CORRECT:**
```cpp
// Create a plugin that extends IoraService
class MicroservicePlugin : public iora::IoraService::Plugin {
  void onLoad(iora::IoraService* svc) override {
    // Register your endpoints and handlers here
  }
};
IORA_DECLARE_PLUGIN(MicroservicePlugin)
```

### Building the Plugin

```bash
# Configure and build
cmake -S . -B build
cmake --build build --target microservice_plugin
```

### Running with the Plugin

1. Use the main Iora application with a configuration that loads your plugin:

```bash
# Copy the sample config
cp sample/config_with_plugin.toml config.toml

# Set your OpenAI API key
export OPENAI_API_KEY="your-api-key-here"

# Run the main Iora application (not the microservice_example!)
./build/src/iora --config config.toml
```

2. The plugin will be loaded automatically and register its endpoints:
   - `POST /summarize` - Queue text summarization requests
   - `POST /status` - Check request status and get results

### Benefits of the Plugin Approach

1. **Separation of Concerns**: Framework initialization is handled by the main application
2. **Modularity**: Multiple plugins can be loaded into a single Iora instance
3. **Configuration Management**: Centralized configuration through TOML files
4. **Lifecycle Management**: Proper plugin loading/unloading with `onLoad`/`onUnload`
5. **Resource Sharing**: All plugins share the same IoraService instance

### Testing the Plugin

```bash
# Start the service (in one terminal)
export OPENAI_API_KEY="your-key"
./build/src/iora --config sample/config_with_plugin.toml

# Submit a summarization request (in another terminal)
curl -X POST http://localhost:8080/summarize \
  -H "Content-Type: application/json" \
  -d '{"text": "This is a long text that needs to be summarized..."}'

# Check the result
curl -X POST http://localhost:8080/status \
  -H "Content-Type: application/json" \
  -d '{"requestId": "returned-request-id"}'
```