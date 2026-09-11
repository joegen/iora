// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// iora flagship example: a TCP echo round trip over the Transport facade, end to
// end in one process.
//
// A server Transport echoes every received buffer straight back on its onData
// callback; a client Transport connects with connectSync, sends one line, and
// receives the echo through its own onData callback. The program exercises the
// headline transport API -- Transport::tcp(), start(), addListener(),
// onAccept/onConnect/onData, connectSync(), and send() -- and verifies the echo
// matches what was sent.
//
// This program is built in CI (BUILD_EXAMPLES=ON): a broken headline API breaks
// the build. It is the flagship snippet referenced from docs/network/transport.md.
//
// NOTE (docs/network/transport.md, Anti-Patterns): transport_impl.hpp carries the
// out-of-line Transport method definitions and MUST be included in EXACTLY ONE
// translation unit. This is that TU.

#include "iora/network/transport_impl.hpp"

#include <chrono>
#include <cstdint>
#include <future>
#include <iostream>
#include <string>

using namespace std::chrono_literals;
using iora::core::BufferView;
using iora::network::SessionId;
using iora::network::TlsMode;
using iora::network::Transport;
using iora::network::TransportAddress;

int main()
{
  const std::string bindIp = "127.0.0.1";
  const std::uint16_t port = 18090;

  // ===== Server: echo every received buffer back to its sender. =====
  auto server = Transport::tcp();

  // Capture the raw pointer, NOT the owning shared_ptr, to avoid the
  // self-reference cycle (docs/network/transport.md, Anti-Patterns). The server
  // outlives every callback here -- it is stopped only at the end of main.
  Transport *srv = server.get();

  server->onAccept([](SessionId sid, const TransportAddress &peer)
                   {
                     std::cout << "server: accepted session " << sid << " from "
                               << peer.host << ":" << peer.port << "\n";
                   });

  server->onData([srv](SessionId sid, BufferView data, std::chrono::steady_clock::time_point)
                 {
                   // send() copies into the write queue, so the BufferView (valid
                   // only for this callback) need not outlive the call.
                   srv->send(sid, data);
                 });

  auto serverStarted = server->start();
  if (!serverStarted)
  {
    std::cerr << "server start failed: " << serverStarted.error().message << "\n";
    return 1;
  }

  auto listening = server->addListener(bindIp, port);
  if (!listening)
  {
    std::cerr << "server listen failed: " << listening.error().message << "\n";
    return 1;
  }

  // ===== Client: connectSync, send one line, receive the echo via onData. =====
  auto client = Transport::tcp();

  std::promise<std::string> echoPromise;
  std::future<std::string> echoFuture = echoPromise.get_future();

  // The client stays in the default async read mode: onData delivers the server's
  // echo. `delivered` is touched only on the client's single I/O thread, so the
  // guard needs no synchronization; the promise/future is the cross-thread handoff.
  bool delivered = false;
  client->onData([&echoPromise, &delivered](SessionId, BufferView data,
                                            std::chrono::steady_clock::time_point)
                 {
                   if (!delivered)
                   {
                     delivered = true;
                     echoPromise.set_value(std::string(
                       reinterpret_cast<const char *>(data.data()), data.size()));
                   }
                 });

  auto clientStarted = client->start();
  if (!clientStarted)
  {
    std::cerr << "client start failed: " << clientStarted.error().message << "\n";
    return 1;
  }

  // connectSync blocks the caller until the connection completes (or the timeout
  // elapses); it does NOT fire the global onConnect.
  auto connected = client->connectSync(bindIp, port, TlsMode::None, 5000ms);
  if (!connected)
  {
    std::cerr << "client connectSync failed: " << connected.error().message << "\n";
    return 1;
  }
  const SessionId sid = connected.value();

  const std::string request = "hello iora transport";
  if (!client->send(sid, request.data(), request.size()))
  {
    std::cerr << "client send failed\n";
    return 1;
  }

  // Wait (bounded) for the echo to arrive on the client's onData callback.
  if (echoFuture.wait_for(5s) != std::future_status::ready)
  {
    std::cerr << "timed out waiting for echo\n";
    return 1;
  }
  const std::string echo = echoFuture.get();
  std::cout << "client: received echo \"" << echo << "\"\n";

  client->stop();
  server->stop();

  if (echo != request)
  {
    std::cerr << "echo mismatch: expected \"" << request << "\", got \"" << echo << "\"\n";
    return 1;
  }

  std::cout << "transport echo round-trip OK\n";
  return 0;
}
