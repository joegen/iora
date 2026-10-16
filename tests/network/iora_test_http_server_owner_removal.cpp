// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// HttpServer / WebhookServer owner tagging, 503 for a closed owner, and removal
// by owner (plugin_callback_ownership C3: H-1..H-7).

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>
#include "iora/core/callback_ownership.hpp"
#include "iora/network/http_server.hpp"
#include "iora/network/webhook_server.hpp"
#include "iora_test_net_utils.hpp" // uses Catch2 REQUIRE -> must follow catch.hpp

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using iora::core::CallbackGate;
using iora::core::CallbackOwner;
using iora::network::HttpServer;
using iora::network::WebhookServer;
using Request = HttpServer::Request;
using Response = HttpServer::Response;

namespace
{

constexpr auto BOUND = std::chrono::seconds(5);

struct Reply
{
  int status = 0;
  std::string head;
  std::string body;
};

/// One request on a fresh connection with Connection: close; reads to EOF.
Reply http(int port, const std::string &method, const std::string &path)
{
  Reply r;
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
  {
    return r;
  }
  timeval tv{};
  tv.tv_sec = 4;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<std::uint16_t>(port));
  ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
  {
    ::close(fd);
    return r;
  }
  const std::string req = method + " " + path +
                          " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                          "Content-Length: 0\r\n\r\n";
  ::send(fd, req.data(), req.size(), MSG_NOSIGNAL);
  std::string raw;
  char buf[4096];
  for (;;)
  {
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n <= 0)
    {
      break;
    }
    raw.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);
  const auto sp = raw.find(' ');
  if (sp != std::string::npos && raw.size() >= sp + 4)
  {
    r.status = std::stoi(raw.substr(sp + 1, 3));
  }
  const auto split = raw.find("\r\n\r\n");
  if (split != std::string::npos)
  {
    r.head = raw.substr(0, split);
    r.body = raw.substr(split + 4);
  }
  return r;
}

HttpServer::Handler body(const std::string &text)
{
  return [text](const Request &, Response &res) { res.set_content(text, "text/plain"); };
}

} // namespace

TEST_CASE("H-1 removeHandlersOwnedBy removes the owner's routes; others keep order",
          "[HttpServer][owner]")
{
  const int port = testnet::getFreePortTCP();
  HttpServer server("127.0.0.1", port);
  server.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("h1.A");
    server.onGet("/a/exact", body("A-exact"));
    server.onPost("/a/post", body("A-post"));
    server.onGet("/items/:id", body("A-named"));
    server.onGet("/static/*", body("A-wild"));
    server.onGet("/q/:a", body("A-q"));
  }
  {
    CallbackOwner::Scope scope("h1.B");
    server.onGet("/items/*", body("B-wild"));
  }
  server.onGet("/host", body("host"));
  server.onGet("/q/:b", body("h1"));
  server.onGet("/q/:c", body("h2"));
  server.start();

  REQUIRE(http(port, "GET", "/a/exact").body == "A-exact");
  REQUIRE(http(port, "GET", "/items/5").body == "A-named");
  REQUIRE(http(port, "GET", "/q/1").body == "A-q");

  server.removeHandlersOwnedBy("h1.A");

  REQUIRE(http(port, "GET", "/a/exact").status == 404);
  REQUIRE(http(port, "POST", "/a/post").status == 404);
  REQUIRE(http(port, "GET", "/static/x").status == 404);
  auto items = http(port, "GET", "/items/5");
  REQUIRE(items.status == 200);
  REQUIRE(items.body == "B-wild");
  REQUIRE(http(port, "GET", "/host").body == "host");
  REQUIRE(http(port, "GET", "/q/1").body == "h1");
  REQUIRE_THROWS_AS(server.removeHandlersOwnedBy(""), std::invalid_argument);
}

TEST_CASE("H-2 a closed owner's route answers 503; Allow and 405 are unchanged",
          "[HttpServer][owner]")
{
  const int port = testnet::getFreePortTCP();
  HttpServer server("127.0.0.1", port);
  server.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("h2.A");
    server.onGet("/h2", body("A"));
  }
  server.start();

  CallbackGate::close("h2.A");
  auto get = http(port, "GET", "/h2");
  auto head = http(port, "HEAD", "/h2");
  auto post = http(port, "POST", "/h2");
  auto options = http(port, "OPTIONS", "/h2");
  CallbackGate::open("h2.A");

  REQUIRE(get.status == 503);
  REQUIRE(get.body == "Service Unavailable");
  REQUIRE(head.status == 503);
  REQUIRE(head.body.empty());
  REQUIRE(post.status == 405);
  REQUIRE(post.head.find("Allow: GET") != std::string::npos);
  REQUIRE(options.status == 204);

  auto after = http(port, "GET", "/h2");
  REQUIRE(after.status == 200);
  REQUIRE(after.body == "A");
}

TEST_CASE("H-3 an owned default handler answers 503 while closed and is removed",
          "[HttpServer][owner]")
{
  const int port = testnet::getFreePortTCP();
  HttpServer server("127.0.0.1", port);
  server.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("h3.A");
    server.setDefaultHandler(body("dflt"));
  }
  server.start();

  CallbackGate::close("h3.A");
  auto closed = http(port, "GET", "/nothing");
  CallbackGate::open("h3.A");
  REQUIRE(closed.status == 503);
  REQUIRE(http(port, "GET", "/nothing").body == "dflt");

  server.removeHandlersOwnedBy("h3.A");
  REQUIRE(http(port, "GET", "/nothing").status == 404);
}

namespace
{
struct RecordAdmittedOnDestroy
{
  std::shared_ptr<std::atomic<int>> record;
  std::thread::id testThread;
  ~RecordAdmittedOnDestroy()
  {
    if (record && std::this_thread::get_id() != testThread)
    {
      record->store(CallbackGate::admittedOnThisThread("h4.A") ? 1 : 0);
    }
  }
};
} // namespace

TEST_CASE("H-4 the handler copy is destroyed while still admitted", "[HttpServer][owner]")
{
  const int port = testnet::getFreePortTCP();
  HttpServer server("127.0.0.1", port);
  server.enableCallbackOwnerTracking();
  auto record = std::make_shared<std::atomic<int>>(-1);
  {
    CallbackOwner::Scope scope("h4.A");
    RecordAdmittedOnDestroy probe{record, std::this_thread::get_id()};
    server.onGet("/h4", [probe](const Request &, Response &res) { res.set_content("ok", "text/plain"); });
    probe.record.reset();
  }
  server.start();
  REQUIRE(http(port, "GET", "/h4").status == 200);
  const auto deadline = std::chrono::steady_clock::now() + BOUND;
  while (record->load() == -1 && std::chrono::steady_clock::now() < deadline)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  REQUIRE(record->load() == 1);
}

TEST_CASE("H-5 WebhookServer JSON routes are tagged and removed", "[HttpServer][owner]")
{
  const int port = testnet::getFreePortTCP();
  WebhookServer server("127.0.0.1", port);
  server.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("h5.A");
    server.onJsonGet("/j/get", [](const iora::parsers::Json &) { return iora::parsers::Json::object(); });
    server.onJsonPost("/j/post", [](const iora::parsers::Json &) { return iora::parsers::Json::object(); });
  }
  server.start();

  CallbackGate::close("h5.A");
  auto closedGet = http(port, "GET", "/j/get");
  CallbackGate::open("h5.A");
  REQUIRE(closedGet.status == 503);
  REQUIRE(http(port, "GET", "/j/get").status == 200);

  server.removeHandlersOwnedBy("h5.A");
  REQUIRE(http(port, "GET", "/j/get").status == 404);
  REQUIRE(http(port, "POST", "/j/post").status == 404);
}

TEST_CASE("H-6 a server that is not opted in never answers 503 or removes", "[HttpServer][owner]")
{
  const int port = testnet::getFreePortTCP();
  HttpServer plain("127.0.0.1", port);
  {
    CallbackOwner::Scope scope("h6.A");
    plain.onGet("/h6", body("route"));
    plain.setDefaultHandler(body("dflt"));
  }
  plain.start();

  CallbackGate::close("h6.A");
  auto route = http(port, "GET", "/h6");
  auto dflt = http(port, "GET", "/zzz");
  plain.removeHandlersOwnedBy("h6.A");
  auto routeAfter = http(port, "GET", "/h6");
  auto dfltAfter = http(port, "GET", "/zzz");

  // Positive control: the same registrations on an opted-in server are gated.
  const int trackedPort = testnet::getFreePortTCP();
  HttpServer tracked("127.0.0.1", trackedPort);
  tracked.enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("h6.A");
    tracked.onGet("/h6", body("route"));
    tracked.setDefaultHandler(body("dflt"));
  }
  tracked.start();
  auto trackedRoute = http(trackedPort, "GET", "/h6");
  auto trackedDflt = http(trackedPort, "GET", "/zzz");
  CallbackGate::open("h6.A");

  REQUIRE(route.status == 200);
  REQUIRE(dflt.body == "dflt");
  REQUIRE(routeAfter.body == "route");
  REQUIRE(dfltAfter.body == "dflt");
  REQUIRE(trackedRoute.status == 503);
  REQUIRE(trackedDflt.status == 503);
}

namespace
{
struct RegisterOnDestroy
{
  HttpServer *server = nullptr;
  ~RegisterOnDestroy()
  {
    if (server)
    {
      server->onGet("/h7/new", body("new"));
    }
  }
};
} // namespace

TEST_CASE("H-7 removed handlers are destroyed off the server lock", "[HttpServer][owner]")
{
  const int port = testnet::getFreePortTCP();
  auto server = std::make_shared<HttpServer>("127.0.0.1", port);
  server->enableCallbackOwnerTracking();
  {
    CallbackOwner::Scope scope("h7.A");
    auto probe = std::make_shared<RegisterOnDestroy>();
    probe->server = server.get();
    server->onGet("/h7/old", [probe](const Request &, Response &res) { res.set_content("old", "text/plain"); });
  }
  server->start();
  REQUIRE(http(port, "GET", "/h7/new").status == 404);

  auto done = std::make_shared<std::promise<void>>();
  auto removed = done->get_future();
  std::thread(
    [server, done]
    {
      server->removeHandlersOwnedBy("h7.A");
      done->set_value();
    })
    .detach();
  if (removed.wait_for(BOUND) != std::future_status::ready)
  {
    // Destroyed under the lock: the worker is stuck on the server mutex and owns
    // the server, so the server is never destroyed under it.
    FAIL("removeHandlersOwnedBy deadlocked: removed handler destroyed under the server lock");
  }
  REQUIRE(http(port, "GET", "/h7/new").body == "new");
  REQUIRE(http(port, "GET", "/h7/old").status == 404);
}
