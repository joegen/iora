// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/network/websocket_frame.hpp"
#include "iora/network/transport_impl.hpp"
#include "iora/crypto/secure_rng.hpp"
#include "iora/util/base64.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace iora {
namespace network {

/// \brief WebSocket connection states.
enum class WebSocketState
{
  DISCONNECTED,
  CONNECTING,
  CONNECTED,
  CLOSING,
  CLOSED
};

/// \brief WebSocket client with auto-reconnect.
///
/// Performs HTTP upgrade handshake, exchanges frames (client-side masking),
/// and optionally auto-reconnects with exponential backoff.
class WebSocketClient
{
public:
  using TextCallback = std::function<void(const std::string&)>;
  using BinaryCallback = std::function<void(const std::vector<std::uint8_t>&)>;
  using ConnectCallback = std::function<void(const std::string& subprotocol)>;
  using CloseCallback = std::function<void(std::uint16_t code, const std::string& reason)>;
  using ErrorCallback = std::function<void(const std::string& message)>;
  using StateCallback = std::function<void(WebSocketState)>;

  struct Options
  {
    bool autoReconnect;
    std::chrono::milliseconds initialReconnectDelay;
    std::chrono::milliseconds maxReconnectDelay;
    std::vector<std::string> subprotocols;
    std::chrono::seconds pingInterval;
    std::unordered_map<std::string, std::string> headers; // custom upgrade headers
    TlsMode tlsMode;

    Options()
      : autoReconnect(false)
      , initialReconnectDelay(1000)
      , maxReconnectDelay(30000)
      , pingInterval(30)
      , tlsMode(TlsMode::None)
    {
    }
  };

  WebSocketClient()
    : _sessionId{0}
    , _state{WebSocketState::DISCONNECTED}
    , _shouldReconnect{false}
  {
  }

  ~WebSocketClient()
  {
    _shouldReconnect.store(false);
    disconnect();
    if (_reconnectThread.joinable())
    {
      _reconnectThread.join();
    }
  }

  WebSocketClient(const WebSocketClient&) = delete;
  WebSocketClient& operator=(const WebSocketClient&) = delete;
  WebSocketClient(WebSocketClient&&) = delete;
  WebSocketClient& operator=(WebSocketClient&&) = delete;

  // ── Callbacks ──────────────────────────────────────────────────────────

  void setOnConnect(ConnectCallback cb) { _onConnect = std::move(cb); }
  void setOnTextMessage(TextCallback cb) { _onTextMessage = std::move(cb); }
  void setOnBinaryMessage(BinaryCallback cb) { _onBinaryMessage = std::move(cb); }
  void setOnClose(CloseCallback cb) { _onClose = std::move(cb); }
  void setOnError(ErrorCallback cb) { _onError = std::move(cb); }
  void setOnStateChange(StateCallback cb) { _onStateChange = std::move(cb); }

  // ── Connect / Disconnect ───────────────────────────────────────────────

  /// \brief Connect to a WebSocket server.
  /// \param host Server hostname or IP
  /// \param port Server port
  /// \param path Request path (e.g., "/ws")
  /// \param options Connection options
  /// \brief Connect to a WebSocket server. Blocks until the handshake
  /// completes (CONNECTED) or fails (DISCONNECTED).
  /// \param timeoutMs Maximum time to wait for connection + upgrade.
  /// \return true if connected, false if failed or timed out.
  bool connect(const std::string& host, std::uint16_t port,
               const std::string& path = "/",
               const Options& options = Options(),
               std::chrono::milliseconds timeoutMs = std::chrono::milliseconds(10000))
  {
    _host = host;
    _port = port;
    _path = path;
    _options = options;
    _shouldReconnect.store(options.autoReconnect);

    doConnect();

    // Block until handshake completes or fails
    {
      std::unique_lock lock(_connectMutex);
      bool completed = _connectCv.wait_for(lock, timeoutMs, [this]()
      {
        auto s = _state.load();
        return s == WebSocketState::CONNECTED || s == WebSocketState::DISCONNECTED
            || s == WebSocketState::CLOSED;
      });

      if (!completed)
      {
        // Timeout — clean up
        setState(WebSocketState::DISCONNECTED);
        if (_transport)
        {
          _transport->stop();
          _transport.reset();
        }
        return false;
      }
    }

    return _state.load() == WebSocketState::CONNECTED;
  }

  /// \brief Disconnect gracefully (close handshake).
  void disconnect(std::uint16_t code = 1000, const std::string& reason = "")
  {
    _shouldReconnect.store(false);

    if (_state.load() == WebSocketState::CONNECTED)
    {
      setState(WebSocketState::CLOSING);
      sendClose(code, reason);
    }

    // Give a moment for close frame to send
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    if (_transport)
    {
      if (_sessionId != 0)
      {
        _transport->close(_sessionId);
      }
      _transport->stop();
      _transport.reset();
    }

    setState(WebSocketState::CLOSED);
    _sessionId = 0;
  }

  // ── Send ───────────────────────────────────────────────────────────────

  void sendText(const std::string& text)
  {
    if (_state.load() != WebSocketState::CONNECTED) return;
    auto frame = WebSocketFrame::makeText(text);
    generateMaskKey(frame.maskKey);
    auto wire = frame.serialize(true); // client MUST mask
    sendRawBytes(wire.data(), wire.size());
  }

  void sendBinary(const std::vector<std::uint8_t>& data)
  {
    if (_state.load() != WebSocketState::CONNECTED) return;
    auto frame = WebSocketFrame::makeBinary(data);
    generateMaskKey(frame.maskKey);
    auto wire = frame.serialize(true);
    sendRawBytes(wire.data(), wire.size());
  }

  void sendPing(const std::vector<std::uint8_t>& payload = {})
  {
    if (_state.load() != WebSocketState::CONNECTED) return;
    auto frame = WebSocketFrame::makePing(payload);
    generateMaskKey(frame.maskKey);
    auto wire = frame.serialize(true);
    sendRawBytes(wire.data(), wire.size());
  }

  void sendClose(std::uint16_t code = 1000, const std::string& reason = "")
  {
    auto frame = WebSocketFrame::makeClose(code, reason);
    generateMaskKey(frame.maskKey);
    auto wire = frame.serialize(true);
    sendRawBytes(wire.data(), wire.size());
  }

  // ── State ──────────────────────────────────────────────────────────────

  WebSocketState getState() const { return _state.load(); }
  std::string negotiatedProtocol() const
  {
    std::lock_guard<std::mutex> lock(_dataMutex);
    return _negotiatedProtocol;
  }

private:
  void doConnect()
  {
    setState(WebSocketState::CONNECTING);

    // Create transport
    TransportConfig config;
    config.protocol = Protocol::TCP;
    config.enableTcpNoDelay = true;

    _transport = std::make_unique<Transport>(config);
    {
      std::lock_guard<std::mutex> lock(_dataMutex);
      _buffer.clear();
      _fragmentBuffer.clear();
      _fragmentOpcode = WsOpcode::CONTINUATION;
    }
    _upgradeComplete.store(false);

    // Set up global data callback before start (new Transport requires global, not per-session)
    _transport->onData(
      [this](SessionId s, iora::core::BufferView data,
             std::chrono::steady_clock::time_point)
      {
        handleData(s, data.data(), data.size());
      });

    _transport->onClose(
      [this](SessionId, const TransportErrorInfo&)
      {
        handleDisconnect();
      });

    _transport->onError(
      [this](TransportError, const std::string& message)
      {
        if (_onError) _onError(message);
      });

    if (_transport->start().isErr())
    {
      setState(WebSocketState::DISCONNECTED);
      if (_onError) _onError("Failed to start transport");
      scheduleReconnect();
      return;
    }

    // Connect — returns ConnectResult
    auto connectResult = _transport->connect(_host, _port, _options.tlsMode);
    if (connectResult.isErr())
    {
      setState(WebSocketState::DISCONNECTED);
      if (_onError) _onError("Failed to connect to " + _host + ":" + std::to_string(_port));
      _transport->stop();
      _transport.reset();
      scheduleReconnect();
      return;
    }
    _sessionId = connectResult.value();

    // Send upgrade request synchronously — sendSync blocks until the
    // TCP connection is established and the data is sent.
    auto upgradeReq = buildUpgradeRequest();
    auto result = _transport->sendSync(
      _sessionId,
      iora::core::BufferView{reinterpret_cast<const std::uint8_t*>(upgradeReq.data()), upgradeReq.size()},
      std::chrono::milliseconds(5000));

    if (result.isErr())
    {
      setState(WebSocketState::DISCONNECTED);
      if (_onError) _onError("Failed to send upgrade: " + result.error().message);
      _transport->close(_sessionId);
      _transport->stop();
      _transport.reset();
      scheduleReconnect();
      return;
    }

    // Data is already flowing via the global onData callback set before start.
  }

  std::string buildUpgradeRequest()
  {
    // Generate random 16-byte key, Base64 encode
    std::uint8_t keyBytes[16];
    crypto::SecureRng::fill(keyBytes, sizeof(keyBytes));
    _wsKey = util::Base64::encode(keyBytes, sizeof(keyBytes));

    std::ostringstream req;
    req << "GET " << _path << " HTTP/1.1\r\n";
    req << "Host: " << _host << ":" << _port << "\r\n";
    req << "Upgrade: websocket\r\n";
    req << "Connection: Upgrade\r\n";
    req << "Sec-WebSocket-Key: " << _wsKey << "\r\n";
    req << "Sec-WebSocket-Version: 13\r\n";

    if (!_options.subprotocols.empty())
    {
      req << "Sec-WebSocket-Protocol: ";
      for (std::size_t i = 0; i < _options.subprotocols.size(); ++i)
      {
        if (i > 0) req << ", ";
        req << _options.subprotocols[i];
      }
      req << "\r\n";
    }

    // Custom headers
    for (const auto& [key, value] : _options.headers)
    {
      req << key << ": " << value << "\r\n";
    }

    req << "\r\n";
    return req.str();
  }

  void handleData(SessionId, const std::uint8_t* data, std::size_t len)
  {
    // Move-parse-callback pattern: buffer ops under lock, callbacks outside.
    // Same pattern as server's onUpgradedData to avoid deadlock.

    // Step 1: append data and move buffer out under lock
    std::vector<std::uint8_t> localBuffer;
    {
      std::lock_guard<std::mutex> lock(_dataMutex);
      _buffer.insert(_buffer.end(), data, data + len);
      localBuffer = std::move(_buffer);
      _buffer.clear();
    }

    // Step 2: Parse HTTP upgrade response (if not yet completed)
    if (!_upgradeComplete.load())
    {
      std::string response(localBuffer.begin(), localBuffer.end());
      auto headerEnd = response.find("\r\n\r\n");
      if (headerEnd == std::string::npos)
      {
        // Incomplete — put back
        std::lock_guard<std::mutex> lock(_dataMutex);
        _buffer.insert(_buffer.begin(), localBuffer.begin(), localBuffer.end());
        return;
      }

      if (response.find("HTTP/1.1 101") == std::string::npos)
      {
        setState(WebSocketState::DISCONNECTED);
        if (_onError) _onError("Upgrade failed: " + response.substr(0, 40));
        return;
      }

      static const std::string kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
      unsigned char sha1Out[20];
      crypto::SecureRng::sha1(_wsKey + kGuid, sha1Out);
      std::string expectedAccept = util::Base64::encode(sha1Out, 20);

      if (response.find(expectedAccept) == std::string::npos)
      {
        setState(WebSocketState::DISCONNECTED);
        if (_onError) _onError("Invalid Sec-WebSocket-Accept");
        return;
      }

      // Extract negotiated subprotocol
      std::string proto;
      auto protoPos = response.find("Sec-WebSocket-Protocol: ");
      if (protoPos != std::string::npos)
      {
        auto lineEnd = response.find("\r\n", protoPos);
        proto = response.substr(protoPos + 24, lineEnd - protoPos - 24);
      }

      {
        std::lock_guard<std::mutex> lock(_dataMutex);
        _negotiatedProtocol = proto;
      }

      _upgradeComplete.store(true);
      setState(WebSocketState::CONNECTED);

      // Callback outside lock
      if (_onConnect)
      {
        _onConnect(proto);
      }

      // Remove HTTP response, keep remaining WebSocket data
      localBuffer.erase(localBuffer.begin(),
                        localBuffer.begin() + headerEnd + 4);
    }

    // Step 3: Parse WebSocket frames (outside lock)
    std::size_t offset = 0;
    while (offset < localBuffer.size())
    {
      core::BufferView view(localBuffer.data() + offset,
                            localBuffer.size() - offset);
      std::size_t consumed = 0;
      auto frame = WebSocketFrame::parse(view, consumed);
      if (!frame) break;
      offset += consumed;

      // handleFrame fires callbacks — must be outside lock
      handleFrame(*frame);
    }

    // Step 4: Put unconsumed remainder back under lock
    if (offset < localBuffer.size())
    {
      std::lock_guard<std::mutex> lock(_dataMutex);
      std::vector<std::uint8_t> remainder(
        localBuffer.begin() + offset, localBuffer.end());
      remainder.insert(remainder.end(), _buffer.begin(), _buffer.end());
      _buffer = std::move(remainder);
    }
  }

  void handleFrame(const WebSocketFrame& frame)
  {
    switch (frame.opcode)
    {
    case WsOpcode::TEXT:
    case WsOpcode::BINARY:
    case WsOpcode::CONTINUATION:
    {
      handleDataFrame(frame);
      break;
    }
    case WsOpcode::PING:
    {
      // Auto-respond with Pong (masked)
      auto pong = WebSocketFrame::makePong(frame.payload);
      generateMaskKey(pong.maskKey);
      auto wire = pong.serialize(true);
      sendRawBytes(wire.data(), wire.size());
      break;
    }
    case WsOpcode::PONG:
    {
      // No-op
      break;
    }
    case WsOpcode::CLOSE:
    {
      auto [code, reason] = frame.closePayload();

      // Echo close frame back per RFC 6455 (if we haven't already sent one)
      if (_state.load() != WebSocketState::CLOSING)
      {
        sendClose(code, reason);
      }

      setState(WebSocketState::CLOSED);
      if (_onClose)
      {
        _onClose(code, reason);
      }
      break;
    }
    default:
      break;
    }
  }

  void handleDataFrame(const WebSocketFrame& frame)
  {
    bool isStart = (frame.opcode == WsOpcode::TEXT || frame.opcode == WsOpcode::BINARY);
    bool isCont = (frame.opcode == WsOpcode::CONTINUATION);

    if (isStart)
    {
      _fragmentOpcode = frame.opcode;
      _fragmentBuffer = frame.payload;
    }
    else if (isCont)
    {
      _fragmentBuffer.insert(_fragmentBuffer.end(),
                              frame.payload.begin(), frame.payload.end());
    }

    if (frame.fin)
    {
      auto opcode = _fragmentOpcode;
      auto payload = std::move(_fragmentBuffer);
      _fragmentBuffer.clear();
      _fragmentOpcode = WsOpcode::CONTINUATION;

      if (opcode == WsOpcode::TEXT)
      {
        if (_onTextMessage)
        {
          std::string text(payload.begin(), payload.end());
          _onTextMessage(text);
        }
      }
      else if (opcode == WsOpcode::BINARY)
      {
        if (_onBinaryMessage)
        {
          _onBinaryMessage(payload);
        }
      }
    }
  }

  void handleDisconnect()
  {
    auto prevState = _state.load();
    if (prevState == WebSocketState::CLOSING || prevState == WebSocketState::CLOSED)
    {
      setState(WebSocketState::CLOSED);
      return;
    }

    setState(WebSocketState::DISCONNECTED);
    scheduleReconnect();
  }

  void scheduleReconnect()
  {
    if (!_shouldReconnect.load()) return;

    if (_reconnectThread.joinable())
    {
      _reconnectThread.join();
    }

    _reconnectThread = std::thread([this]()
    {
      auto delay = _options.initialReconnectDelay;

      while (_shouldReconnect.load())
      {
        std::this_thread::sleep_for(delay);
        if (!_shouldReconnect.load()) break;

        // Clean up previous transport
        if (_transport)
        {
          _transport->stop();
          _transport.reset();
        }
        _sessionId = 0;
        {
          std::lock_guard<std::mutex> lock(_dataMutex);
          _buffer.clear();
          _fragmentBuffer.clear();
          _fragmentOpcode = WsOpcode::CONTINUATION;
        }
        _upgradeComplete.store(false);

        doConnect();

        if (_state.load() == WebSocketState::CONNECTED)
        {
          break; // reconnected successfully
        }

        // Exponential backoff
        delay = std::min(delay * 2, _options.maxReconnectDelay);
      }
    });
  }

  void sendRawBytes(const std::uint8_t* data, std::size_t len)
  {
    if (_transport && _sessionId != 0)
    {
      auto shared = std::make_shared<std::vector<std::uint8_t>>(data, data + len);
      _transport->sendAsync(_sessionId, shared->data(), shared->size(),
        [shared](SessionId, const SendResult&) {});
    }
  }

  void generateMaskKey(std::uint8_t key[4])
  {
    crypto::SecureRng::fill(key, 4);
  }

  void setState(WebSocketState newState)
  {
    _state.store(newState);

    // Signal the blocking connect() call
    _connectCv.notify_all();

    if (_onStateChange)
    {
      _onStateChange(newState);
    }
  }

  // Connection params
  std::string _host;
  std::uint16_t _port = 0;
  std::string _path;
  Options _options;

  // Transport
  std::unique_ptr<Transport> _transport;
  SessionId _sessionId;

  // State
  std::atomic<WebSocketState> _state;
  std::string _wsKey;
  std::string _negotiatedProtocol;

  // Receive buffer (protected by _dataMutex)
  mutable std::mutex _dataMutex;
  std::vector<std::uint8_t> _buffer;
  std::atomic<bool> _upgradeComplete{false};

  // Fragment reassembly (protected by _dataMutex)
  std::vector<std::uint8_t> _fragmentBuffer;
  WsOpcode _fragmentOpcode = WsOpcode::CONTINUATION;

  // Connect synchronization
  std::mutex _connectMutex;
  std::condition_variable _connectCv;

  // Auto-reconnect
  std::atomic<bool> _shouldReconnect;
  std::thread _reconnectThread;

  // Callbacks
  ConnectCallback _onConnect;
  TextCallback _onTextMessage;
  BinaryCallback _onBinaryMessage;
  CloseCallback _onClose;
  ErrorCallback _onError;
  StateCallback _onStateChange;
};

} // namespace network
} // namespace iora
