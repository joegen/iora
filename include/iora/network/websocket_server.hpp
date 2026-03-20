// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include "iora/network/http_server.hpp"
#include "iora/network/websocket_frame.hpp"
#include "iora/crypto/secure_rng.hpp"
#include "iora/util/base64.hpp"

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace iora {
namespace network {

/// \brief WebSocket server extending HttpServer via onUpgradeRequest().
///
/// Handles RFC 6455 handshake, frame parsing, fragment reassembly,
/// Ping/Pong, close handshake. Callbacks: onConnect, onMessage, onClose, onError.
class WebSocketServer : public HttpServer
{
public:
  using MessageCallback = std::function<void(SessionId, const std::string&)>;
  using BinaryCallback = std::function<void(SessionId, const std::vector<std::uint8_t>&)>;
  using ConnectCallback = std::function<void(SessionId, const std::string& subprotocol)>;
  using CloseCallback = std::function<void(SessionId, std::uint16_t code, const std::string& reason)>;
  using ErrorCallback = std::function<void(SessionId, const std::string& message)>;
  using SubprotocolCallback = std::function<std::string(const std::vector<std::string>&)>;
  using OriginCallback = std::function<bool(SessionId, const std::string& origin)>;

  WebSocketServer(const std::string& bindAddress = "0.0.0.0", int port = DEFAULT_PORT)
    : HttpServer(bindAddress, port)
    , _maxFrameSize(16 * 1024 * 1024) // 16MB default
  {
  }

  // ── Callback Registration ──────────────────────────────────────────────

  void setOnConnect(ConnectCallback cb) { _onConnect = std::move(cb); }
  void setOnTextMessage(MessageCallback cb) { _onTextMessage = std::move(cb); }
  void setOnBinaryMessage(BinaryCallback cb) { _onBinaryMessage = std::move(cb); }
  void setOnClose(CloseCallback cb) { _onClose = std::move(cb); }
  void setOnError(ErrorCallback cb) { _onError = std::move(cb); }
  void setSubprotocolCallback(SubprotocolCallback cb) { _subprotocolCb = std::move(cb); }
  void setOriginCallback(OriginCallback cb) { _originCb = std::move(cb); }

  void setMaxFrameSize(std::size_t maxBytes) { _maxFrameSize = maxBytes; }

  // ── Session Send Methods ───────────────────────────────────────────────

  /// \brief Send a text message to a WebSocket session.
  void sendText(SessionId sid, const std::string& text)
  {
    auto frame = WebSocketFrame::makeText(text);
    auto wire = frame.serialize(false); // server does NOT mask
    sendRaw(sid, wire.data(), wire.size());
  }

  /// \brief Send a binary message to a WebSocket session.
  void sendBinary(SessionId sid, const std::vector<std::uint8_t>& data)
  {
    auto frame = WebSocketFrame::makeBinary(data);
    auto wire = frame.serialize(false);
    sendRaw(sid, wire.data(), wire.size());
  }

  /// \brief Send a Ping to a WebSocket session.
  void sendPing(SessionId sid, const std::vector<std::uint8_t>& payload = {})
  {
    auto frame = WebSocketFrame::makePing(payload);
    auto wire = frame.serialize(false);
    sendRaw(sid, wire.data(), wire.size());
  }

  /// \brief Send a Close frame to a WebSocket session.
  void sendClose(SessionId sid, std::uint16_t code = 1000,
                 const std::string& reason = "")
  {
    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      auto it = _sessions.find(sid);
      if (it != _sessions.end())
      {
        it->second.closeSent = true;
      }
    }

    auto frame = WebSocketFrame::makeClose(code, reason);
    auto wire = frame.serialize(false);
    sendRaw(sid, wire.data(), wire.size());
  }

protected:
  // ── HTTP Upgrade Hook ──────────────────────────────────────────────────

  bool onUpgradeRequest(SessionId sid, const Request& req, Response& res) override
  {
    // Validate required headers
    auto upgradeVal = req.get_header_value("Upgrade");
    auto connectionVal = req.get_header_value("Connection");
    auto wsKey = req.get_header_value("Sec-WebSocket-Key");
    auto wsVersion = req.get_header_value("Sec-WebSocket-Version");

    // Case-insensitive check for "websocket" in Upgrade
    std::string upgradeLower = upgradeVal;
    std::transform(upgradeLower.begin(), upgradeLower.end(), upgradeLower.begin(), ::tolower);
    if (upgradeLower != "websocket")
    {
      return false; // not a WebSocket upgrade
    }

    // Validate Connection contains "Upgrade" (case-insensitive)
    std::string connLower = connectionVal;
    std::transform(connLower.begin(), connLower.end(), connLower.begin(), ::tolower);
    if (connLower.find("upgrade") == std::string::npos)
    {
      res.status = 400;
      res.set_content("Missing Connection: Upgrade", "text/plain");
      return true;
    }

    if (wsKey.empty())
    {
      res.status = 400;
      res.set_content("Missing Sec-WebSocket-Key", "text/plain");
      return true;
    }

    if (wsVersion != "13")
    {
      res.status = 426;
      res.set_header("Sec-WebSocket-Version", "13");
      res.set_content("Unsupported WebSocket version", "text/plain");
      return true;
    }

    // Origin validation (RFC 6455 Section 10.2)
    if (_originCb)
    {
      auto origin = req.get_header_value("Origin");
      if (!_originCb(sid, origin))
      {
        res.status = 403;
        res.set_content("Origin not allowed", "text/plain");
        return true;
      }
    }

    // Compute Sec-WebSocket-Accept
    static const std::string kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string concat = wsKey + kGuid;
    unsigned char sha1Out[20];
    crypto::SecureRng::sha1(concat, sha1Out);
    std::string accept = util::Base64::encode(sha1Out, 20);

    // Negotiate subprotocol
    std::string negotiatedProtocol;
    auto requestedProtocols = req.get_header_value("Sec-WebSocket-Protocol");
    if (!requestedProtocols.empty() && _subprotocolCb)
    {
      // Parse comma-separated protocol list
      std::vector<std::string> protocols;
      std::istringstream ss(requestedProtocols);
      std::string proto;
      while (std::getline(ss, proto, ','))
      {
        // Trim whitespace
        auto start = proto.find_first_not_of(" \t");
        auto end = proto.find_last_not_of(" \t");
        if (start != std::string::npos)
        {
          protocols.push_back(proto.substr(start, end - start + 1));
        }
      }
      negotiatedProtocol = _subprotocolCb(protocols);
    }

    // Build 101 Switching Protocols response
    res.status = 101;
    res.set_header("Upgrade", "websocket");
    res.set_header("Connection", "Upgrade");
    res.set_header("Sec-WebSocket-Accept", accept);
    if (!negotiatedProtocol.empty())
    {
      res.set_header("Sec-WebSocket-Protocol", negotiatedProtocol);
    }

    // Mark session as upgraded
    markSessionUpgraded(sid);

    // Create per-session state
    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      _sessions[sid] = WsSessionState{};
      _sessions[sid].negotiatedProtocol = negotiatedProtocol;
    }

    // Fire onConnect callback
    if (_onConnect)
    {
      _onConnect(sid, negotiatedProtocol);
    }

    return true;
  }

  // ── Upgraded Data Handler ──────────────────────────────────────────────

  void onUpgradedData(SessionId sid, const std::uint8_t* data,
                      std::size_t len) override
  {
    // Move buffer out under lock to avoid TOCTOU race with concurrent calls.
    // Parse on the moved buffer, then put unconsumed remainder back.
    std::vector<std::uint8_t> localBuffer;
    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      auto it = _sessions.find(sid);
      if (it == _sessions.end())
      {
        return;
      }
      it->second.buffer.insert(it->second.buffer.end(), data, data + len);
      localBuffer = std::move(it->second.buffer);
      it->second.buffer.clear();
    }

    // Parse frames from the local buffer (outside lock)
    std::size_t offset = 0;
    while (offset < localBuffer.size())
    {
      core::BufferView view(localBuffer.data() + offset,
                            localBuffer.size() - offset);
      std::size_t consumed = 0;
      auto frame = WebSocketFrame::parse(view, consumed);

      if (!frame)
      {
        break;
      }

      offset += consumed;
      handleFrame(sid, *frame);
    }

    // Put unconsumed remainder back
    if (offset < localBuffer.size())
    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      auto it = _sessions.find(sid);
      if (it != _sessions.end())
      {
        // Prepend remainder before any data that arrived during parsing
        auto& buf = it->second.buffer;
        std::vector<std::uint8_t> remainder(
          localBuffer.begin() + offset, localBuffer.end());
        remainder.insert(remainder.end(), buf.begin(), buf.end());
        buf = std::move(remainder);
      }
    }
  }

private:
  void handleFrame(SessionId sid, const WebSocketFrame& frame)
  {
    switch (frame.opcode)
    {
    case WsOpcode::TEXT:
    case WsOpcode::BINARY:
    case WsOpcode::CONTINUATION:
    {
      handleDataFrame(sid, frame);
      break;
    }
    case WsOpcode::PING:
    {
      // Auto-respond with Pong
      auto pong = WebSocketFrame::makePong(frame.payload);
      auto wire = pong.serialize(false);
      sendRaw(sid, wire.data(), wire.size());
      break;
    }
    case WsOpcode::PONG:
    {
      // No-op — application can track keep-alive if needed
      break;
    }
    case WsOpcode::CLOSE:
    {
      auto [code, reason] = frame.closePayload();

      // Only echo close if we haven't already sent one (prevents infinite loop)
      {
        std::lock_guard<std::mutex> lock(_wsMutex);
        auto it = _sessions.find(sid);
        if (it != _sessions.end() && !it->second.closeSent)
        {
          it->second.closeSent = true;
          auto closeResp = WebSocketFrame::makeClose(code, reason);
          auto wire = closeResp.serialize(false);
          sendRaw(sid, wire.data(), wire.size());
        }
      }

      if (_onClose)
      {
        _onClose(sid, code, reason);
      }

      {
        std::lock_guard<std::mutex> lock(_wsMutex);
        _sessions.erase(sid);
      }

      closeSession(sid);
      break;
    }
    default:
    {
      // Unknown/reserved opcode — protocol error (1002)
      sendClose(sid, 1002, "Unsupported opcode");
      if (_onError)
      {
        _onError(sid, "Received reserved/unknown opcode");
      }
      break;
    }
    }
  }

  void handleDataFrame(SessionId sid, const WebSocketFrame& frame)
  {
    bool isStart = (frame.opcode == WsOpcode::TEXT || frame.opcode == WsOpcode::BINARY);
    bool isContinuation = (frame.opcode == WsOpcode::CONTINUATION);

    // Accumulate under lock, then deliver outside lock
    bool messageComplete = false;
    bool tooLarge = false;
    WsOpcode messageOpcode = WsOpcode::CONTINUATION;
    std::vector<std::uint8_t> messagePayload;

    {
      std::lock_guard<std::mutex> lock(_wsMutex);
      auto it = _sessions.find(sid);
      if (it == _sessions.end())
      {
        return;
      }
      auto& session = it->second;

      if (isStart)
      {
        session.fragmentOpcode = frame.opcode;
        session.fragmentBuffer = frame.payload;
      }
      else if (isContinuation)
      {
        session.fragmentBuffer.insert(session.fragmentBuffer.end(),
                                       frame.payload.begin(), frame.payload.end());
      }

      if (session.fragmentBuffer.size() > _maxFrameSize)
      {
        tooLarge = true;
      }
      else if (frame.fin)
      {
        messageComplete = true;
        messageOpcode = session.fragmentOpcode;
        messagePayload = std::move(session.fragmentBuffer);
        session.fragmentBuffer.clear();
        session.fragmentOpcode = WsOpcode::CONTINUATION;
      }
    }

    // Fire callbacks outside lock
    if (tooLarge)
    {
      sendClose(sid, 1009, "Message Too Big");
      if (_onError)
      {
        _onError(sid, "Message exceeded maxFrameSize");
      }
      return;
    }

    if (messageComplete)
    {
      if (messageOpcode == WsOpcode::TEXT)
      {
        WebSocketFrame temp;
        temp.payload = messagePayload;
        if (!temp.isValidUtf8())
        {
          sendClose(sid, 1007, "Invalid UTF-8");
          return;
        }

        if (_onTextMessage)
        {
          std::string text(messagePayload.begin(), messagePayload.end());
          _onTextMessage(sid, text);
        }
      }
      else if (messageOpcode == WsOpcode::BINARY)
      {
        if (_onBinaryMessage)
        {
          _onBinaryMessage(sid, messagePayload);
        }
      }
    }
  }

  struct WsSessionState
  {
    std::vector<std::uint8_t> buffer;
    std::vector<std::uint8_t> fragmentBuffer;
    WsOpcode fragmentOpcode = WsOpcode::CONTINUATION;
    std::string negotiatedProtocol;
    bool closeSent = false; // prevents double close-frame echo
  };

  std::mutex _wsMutex;
  std::unordered_map<SessionId, WsSessionState> _sessions;
  std::size_t _maxFrameSize;

  // Callbacks
  ConnectCallback _onConnect;
  MessageCallback _onTextMessage;
  BinaryCallback _onBinaryMessage;
  CloseCallback _onClose;
  ErrorCallback _onError;
  SubprotocolCallback _subprotocolCb;
  OriginCallback _originCb;
};

} // namespace network
} // namespace iora
