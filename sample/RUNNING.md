# LLM‑Powered Summarisation Microservice

## Overview

This example microservice demonstrates how to build a real‑world application using the unified `IoraService` API.  The service accepts raw text from clients, forwards it to a large language model (LLM) provider (such as OpenAI) to generate a concise summary, caches recent summaries to avoid redundant LLM calls, logs all activity, and persists configuration and usage data between restarts.

The microservice exposes a simple HTTP API via the embedded `WebhookServer` and uses `HttpClient` to make outbound requests to the LLM backend.  It reads its settings from a TOML file, supports command‑line overrides, and stores persistent values—such as API tokens and usage counters—in a JSON file.

## Demonstrated Features

This application exercises all major components of `IoraService`:

- **Singleton and configuration**: Initialised once via `IoraService::init()` with a Config object, reading configuration from `config.toml`.
- **HTTP server**: Registers JSON endpoints (e.g., `/summarise`) using `webhookServer().onJson()` to handle POST requests.
- **HTTP client**: Uses `makeHttpClient()` to POST requests to the LLM API and parse JSON responses.
- **Cache**: Caches summaries keyed by a hash of the input text via `cache().set()`/`get()`, expiring them after a configurable TTL.
- **State store**: Uses the in‑memory store for transient values and the `jsonFileStore()` to persist API tokens and usage counters across runs.
- **Logging**: Configures the logger (level, base file name, async mode, retention, timestamp format) through the TOML file or CLI flags; all key operations are logged.
- **Concurrency**: Handles concurrent requests safely—each thread uses its own `HttpClient` instance obtained from `makeHttpClient()`.

## Sample `config.toml`

Below is an example configuration file.  You can adjust the values to suit your environment:

```toml
# config.toml

# HTTP server configuration
[server]
# Port on which the WebhookServer listens
port = 8080

# Persistent state configuration
[state]
# Path to the file used by JsonFileStore
file = "state.json"

# Logging configuration
[log]
level = "info"                   # trace, debug, info, warning, error, fatal
file  = "summarisation"          # base name; rotated daily
async = true                     # asynchronous logging
retention_days = 7               # days to keep old logs
time_format = "%Y-%m-%d %H:%M:%S"  # timestamp format

# LLM provider settings
[llm]
api_url    = "https://api.openai.com/v1/chat/completions"
api_model  = "gpt-3.5-turbo"
max_tokens = 256
cache_ttl  = 300  # seconds
