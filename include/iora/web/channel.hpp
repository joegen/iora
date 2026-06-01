// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Live-update channel pub/sub for iora HTMX support: SseChannel (SSE fan-out)
// and WsChannel (WebSocket push). Per-channel std::mutex (OQ-4, LEAF lock),
// snapshot-then-write fan-out — never holds a lock across a socket write or
// callback (LD-4).
//
// Tracker: 2026-05-29-7 (htmx-support phase 6).
// Architecture: architecture/iora/sse_and_channels.json.

#pragma once

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "iora/core/logger.hpp"
#include "iora/network/sse_stream.hpp"
#include "iora/network/transport_types.hpp"
#include "iora/network/websocket_server.hpp"

namespace iora
{
namespace web
{

/// \brief Named pub/sub channel for SSE. Per-channel std::mutex (LEAF);
/// snapshot-then-write fan-out; auto-prune of closed streams. publish() is
/// callable from ANY thread and never blocks the publisher or writes under the
/// lock (LD-4).
class SseChannel
{
public:
  explicit SseChannel(std::string name) : _name(std::move(name)) {}

  SseChannel(const SseChannel &) = delete;
  SseChannel &operator=(const SseChannel &) = delete;

  /// \brief The channel name (diagnostics/metrics).
  const std::string &name() const { return _name; }

  /// \brief Subscribe a stream (shared_ptr co-ownership makes disconnect-driven
  /// removal safe). Brief lock.
  void subscribe(std::shared_ptr<network::SseStream> stream)
  {
    if (!stream)
    {
      return;
    }
    std::lock_guard<std::mutex> lock(_mutex);
    _subscribers.push_back(std::move(stream));
  }

  /// \brief Fan out an SSE event to every open subscriber: snapshot under the
  /// lock (pruning closed entries), release, then writeEvent on each open stream
  /// with NO lock held. Zero-subscriber publish is a no-op. Callable from any
  /// thread (LD-4).
  void publish(std::string_view eventName, std::string_view htmlFragment)
  {
    std::vector<std::shared_ptr<network::SseStream>> snapshot;
    {
      std::lock_guard<std::mutex> lock(_mutex);
      _subscribers.erase(
        std::remove_if(_subscribers.begin(), _subscribers.end(),
                       [](const std::shared_ptr<network::SseStream> &s)
                       { return !s || !s->isOpen(); }),
        _subscribers.end());
      snapshot = _subscribers;
    }
    for (auto &s : snapshot)
    {
      if (s->isOpen())
      {
        s->writeEvent(eventName, htmlFragment);
      }
    }
  }

  /// \brief Subscriber count (source for the OQ-8 gauge). Brief lock.
  std::size_t subscriberCount() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _subscribers.size();
  }

  /// \brief Erase streams whose isOpen() is false. Brief lock.
  void removeClosed()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _subscribers.erase(
      std::remove_if(_subscribers.begin(), _subscribers.end(),
                     [](const std::shared_ptr<network::SseStream> &s)
                     { return !s || !s->isOpen(); }),
      _subscribers.end());
  }

private:
  std::string _name;
  mutable std::mutex _mutex; // guards _subscribers only (OQ-4, LEAF; mutable for const subscriberCount)
  std::vector<std::shared_ptr<network::SseStream>> _subscribers;
};

/// \brief Named pub/sub channel for WebSocket push. Keeps its OWN SessionId set
/// (WebSocketServer::_sessions is private with no enumeration, OQ-6); calls
/// sendText per subscriber, skipping sessions failing isSessionActive. Push-only
/// in v1 (no inbound handling). Per-channel std::mutex (LEAF).
class WsChannel
{
public:
  explicit WsChannel(std::string name) : _name(std::move(name)) {}

  WsChannel(const WsChannel &) = delete;
  WsChannel &operator=(const WsChannel &) = delete;

  const std::string &name() const { return _name; }

  /// \brief Subscribe a session. Records the server on first subscribe; all
  /// subscribers of one channel share one server in v1 (L-1: a subscribe with a
  /// DIFFERENT server is logged and ignored). Brief lock.
  void subscribe(network::WebSocketServer &server, network::SessionId sid)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_server == nullptr)
    {
      _server = &server;
    }
    else if (_server != &server)
    {
      iora::core::Logger::warning(
        "WsChannel '" + _name +
        "': subscribe with a different WebSocketServer ignored (v1 is one server "
        "per channel)");
      return;
    }
    _subscribers.insert(sid);
  }

  /// \brief Fan out an HTML fragment to every active subscriber: snapshot under
  /// the lock, release, then for each sid skip+prune if !isSessionActive else
  /// sendText with NO channel lock held. The data-after-close GUARANTEE is the
  /// send-boundary closeSent recheck inside sendText (web-M7). Callable from any
  /// thread.
  void publish(std::string_view htmlFragment)
  {
    network::WebSocketServer *server = nullptr;
    std::vector<network::SessionId> snapshot;
    {
      std::lock_guard<std::mutex> lock(_mutex);
      server = _server;
      snapshot.assign(_subscribers.begin(), _subscribers.end());
    }
    if (server == nullptr)
    {
      return; // no subscribers yet
    }
    std::vector<network::SessionId> inactive;
    const std::string fragment(htmlFragment);
    for (network::SessionId sid : snapshot)
    {
      if (!server->isSessionActive(sid))
      {
        inactive.push_back(sid);
        continue;
      }
      server->sendText(sid, fragment);
    }
    if (!inactive.empty())
    {
      // Benign TOCTOU (cpp17-L3): a sid found inactive in the snapshot is erased
      // under a second lock acquisition; if it was unsubscribed-then-resubscribed
      // in between, the fresh subscription is dropped. Acceptable for v1 — publish
      // vs subscribe is inherently racy and a dropped re-subscribe is re-added on
      // the next subscribe; no correctness or safety impact.
      std::lock_guard<std::mutex> lock(_mutex);
      for (network::SessionId sid : inactive)
      {
        _subscribers.erase(sid);
      }
    }
  }

  /// \brief Subscriber count. Brief lock.
  std::size_t subscriberCount() const
  {
    std::lock_guard<std::mutex> lock(_mutex);
    return _subscribers.size();
  }

  /// \brief Remove a session. Invoked from a WS close hook which may run under
  /// WebSocketServer::_wsMutex (thread-M4) — therefore it takes ONLY the channel
  /// _mutex and NEVER calls back into the server, keeping the channel _mutex a
  /// strict LEAF and preserving the _wsMutex -> _mutex ordering.
  void unsubscribe(network::SessionId sid)
  {
    std::lock_guard<std::mutex> lock(_mutex);
    _subscribers.erase(sid);
  }

private:
  std::string _name;
  network::WebSocketServer *_server{nullptr}; // set on first subscribe
  mutable std::mutex _mutex;                   // guards _subscribers (OQ-4, LEAF)
  std::unordered_set<network::SessionId> _subscribers;
};

} // namespace web
} // namespace iora
