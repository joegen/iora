
// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <iterator>
#include <map>
#include <mutex>
#include <queue>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "iora/core/callback_ownership.hpp"
#include "iora/core/logger.hpp"
#include "iora/parsers/json.hpp"

namespace iora
{
namespace core
{

/// \brief Thread-safe event queue for dispatching JSON events to registered
/// handlers using worker threads.
class EventQueue
{
public:
  using Handler = std::function<void(const parsers::Json &)>;

  /// \brief Construct the event queue and spin up worker threads
  EventQueue(std::size_t threadCount = std::thread::hardware_concurrency())
  {
    iora::core::Logger::info("EventQueue: Initializing with " + std::to_string(threadCount) +
                             " worker threads");
    for (std::size_t i = 0; i < threadCount; ++i)
    {
      _threads.emplace_back([this, i]() { this->workerLoop(i); });
    }
    iora::core::Logger::info("EventQueue: All worker threads started successfully");
  }

  /// \brief Destructor gracefully shuts down the worker threads
  ~EventQueue()
  {
    iora::core::Logger::debug("EventQueue: Starting shutdown process");
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _shutdown = true;
    }

    _cv.notify_all();

    for (auto &thread : _threads)
    {
      if (thread.joinable())
      {
        thread.join();
      }
    }
    iora::core::Logger::debug("EventQueue: All worker threads shut down successfully");
  }

  /// \brief Enqueue an event for processing
  void push(const parsers::Json &event)
  {
    if (!isValidEvent(event))
    {
      iora::core::Logger::error("EventQueue: Dropping invalid event - "
                                "missing eventId or eventName fields");
      return; // drop invalid event
    }

    std::string eventId = event["eventId"].get<std::string>();
    std::string eventName = event["eventName"].get<std::string>();

    {
      std::unique_lock<std::mutex> lock(_mutex);
      _queue.push(event);
      iora::core::Logger::debug("EventQueue: Enqueued event (id=" + eventId + ", name=" +
                                eventName + ") - queue size: " + std::to_string(_queue.size()));
    }

    _cv.notify_one();
  }

  /// \brief Register a handler for an exact eventId
  void onEventId(const std::string &eventId, Handler handler)
  {
    std::unique_lock<std::mutex> lock(_mutex);
    _handlersById[eventId].push_back(OwnedHandler{ownerForNewEntry(), std::move(handler)});
    iora::core::Logger::info(
      "EventQueue: Registered handler for event ID: " + eventId +
      " (total handlers for this ID: " + std::to_string(_handlersById[eventId].size()) + ")");
  }

  /// \brief Register a handler for an exact eventName
  void onEventName(const std::string &eventName, Handler handler)
  {
    std::unique_lock<std::mutex> lock(_mutex);
    _handlersByName[eventName].push_back(OwnedHandler{ownerForNewEntry(), std::move(handler)});
    iora::core::Logger::info(
      "EventQueue: Registered handler for event name: " + eventName +
      " (total handlers for this name: " + std::to_string(_handlersByName[eventName].size()) + ")");
  }

  /// \brief Register a handler for an eventName using regex matching
  void onEventNameMatches(const std::string &eventNamePattern, Handler handler)
  {
    std::unique_lock<std::mutex> lock(_mutex);
    try
    {
      _compiledHandlersByName[eventNamePattern] =
        PatternHandler{std::regex(eventNamePattern), ownerForNewEntry(), std::move(handler)};
      iora::core::Logger::info("EventQueue: Registered pattern handler for event name pattern: " +
                               eventNamePattern);
    }
    catch (const std::exception &e)
    {
      iora::core::Logger::error("EventQueue: Failed to register pattern "
                                "handler for invalid regex: " +
                                eventNamePattern + " - " + e.what());
      throw;
    }
  }

  /// \brief Record the CallbackOwner of every later registration on this
  /// instance. One-way; earlier entries stay unowned.
  void enableCallbackOwnerTracking() noexcept
  {
    _tracksCallbackOwners.store(true, std::memory_order_relaxed);
  }

  /// \brief Remove every handler (by id, by name and by pattern) registered
  /// under `owner`. Removed handlers are destroyed after the queue lock is
  /// released. Does not wait for invocations already running; the caller drains
  /// the owner first (CallbackGate::drain).
  /// \throws std::invalid_argument if owner is empty.
  void removeHandlersOwnedBy(const std::string &owner)
  {
    if (owner.empty())
    {
      throw std::invalid_argument("EventQueue::removeHandlersOwnedBy: owner must not be empty");
    }
    std::vector<Handler> removed;
    std::unique_lock<std::mutex> lock(_mutex);
    const auto removeFrom = [&removed, &owner](std::map<std::string, std::vector<OwnedHandler>> &map)
    {
      for (auto it = map.begin(); it != map.end();)
      {
        auto &entries = it->second;
        for (auto e = entries.begin(); e != entries.end();)
        {
          if (e->owner == owner)
          {
            removed.push_back(std::move(e->handler));
            e = entries.erase(e);
          }
          else
          {
            ++e;
          }
        }
        it = entries.empty() ? map.erase(it) : std::next(it);
      }
    };
    removeFrom(_handlersById);
    removeFrom(_handlersByName);
    for (auto it = _compiledHandlersByName.begin(); it != _compiledHandlersByName.end();)
    {
      if (it->second.owner == owner)
      {
        removed.push_back(std::move(it->second.handler));
        it = _compiledHandlersByName.erase(it);
      }
      else
      {
        ++it;
      }
    }
    lock.unlock();
  }

private:
  struct OwnedHandler
  {
    std::string owner;
    Handler handler;
  };

  struct PatternHandler
  {
    std::regex pattern;
    std::string owner;
    Handler handler;
  };

  using AdmittedHandler = std::pair<CallbackGate::Admission, Handler>;

  std::string ownerForNewEntry() const
  {
    return _tracksCallbackOwners.load(std::memory_order_relaxed) ? CallbackOwner::current()
                                                                 : std::string();
  }

  bool isValidEvent(const parsers::Json &event) const
  {
    return event.contains("eventId") && event.contains("eventName");
  }

  // Lock order: _mutex -> CallbackGate mutex (admit() in dispatch). The gate
  // mutex is a leaf.
  std::mutex _mutex;
  std::condition_variable _cv;
  std::queue<parsers::Json> _queue;
  std::map<std::string, std::vector<OwnedHandler>> _handlersById;
  std::map<std::string, std::vector<OwnedHandler>> _handlersByName;
  std::map<std::string, PatternHandler> _compiledHandlersByName;
  std::atomic<bool> _tracksCallbackOwners{false};
  std::vector<std::thread> _threads;
  bool _shutdown = false;

  void workerLoop(std::size_t workerId)
  {
    iora::core::Logger::debug("EventQueue: Worker thread " + std::to_string(workerId) + " started");
    while (true)
    {
      parsers::Json event;

      {
        std::unique_lock<std::mutex> lock(_mutex);
        _cv.wait(lock, [this]() { return !_queue.empty() || _shutdown; });

        if (_shutdown && _queue.empty())
        {
          iora::core::Logger::debug("EventQueue: Worker thread " + std::to_string(workerId) +
                                    " shutting down");
          return;
        }

        event = _queue.front();
        _queue.pop();
      }

      dispatch(event, workerId);
    }
  }

  void dispatch(const parsers::Json &event, std::size_t workerId)
  {
    const std::string eventId = event["eventId"];
    const std::string eventName = event["eventName"];

    bool handled = false;
    std::size_t totalHandlers = 0;

    std::vector<AdmittedHandler> idHandlers;
    std::vector<AdmittedHandler> nameHandlers;
    std::size_t skippedClosed = 0;
    std::size_t admitFailed = 0;

    {
      std::unique_lock<std::mutex> lock(_mutex);

      const auto admitAndCopy =
        [&skippedClosed, &admitFailed](std::vector<AdmittedHandler> &out, const std::string &owner,
                                       const Handler &handler)
      {
        try
        {
          auto a = CallbackGate::admit(owner);
          if (!a)
          {
            ++skippedClosed;
            return;
          }
          out.emplace_back(std::move(a), handler);
        }
        catch (const std::exception &)
        {
          ++admitFailed;
        }
      };

      auto idHandlersIt = _handlersById.find(eventId);
      if (idHandlersIt != _handlersById.end())
      {
        for (const auto &entry : idHandlersIt->second)
        {
          admitAndCopy(idHandlers, entry.owner, entry.handler);
        }
      }

      auto nameHandlersIt = _handlersByName.find(eventName);
      if (nameHandlersIt != _handlersByName.end())
      {
        for (const auto &entry : nameHandlersIt->second)
        {
          admitAndCopy(nameHandlers, entry.owner, entry.handler);
        }
      }

      for (const auto &[pattern, compiledHandler] : _compiledHandlersByName)
      {
        if (std::regex_match(eventName, compiledHandler.pattern))
        {
          admitAndCopy(nameHandlers, compiledHandler.owner, compiledHandler.handler);
        }
      }
    }

    if (skippedClosed > 0)
    {
      iora::core::Logger::debug("EventQueue: Worker " + std::to_string(workerId) + " skipped " +
                                std::to_string(skippedClosed) +
                                " handler(s) of a closed owner for event (id=" + eventId +
                                ", name=" + eventName + ")");
    }
    if (admitFailed > 0)
    {
      iora::core::Logger::error("EventQueue: Worker " + std::to_string(workerId) + " skipped " +
                                std::to_string(admitFailed) +
                                " handler(s): owner admission failed for event (id=" + eventId +
                                ", name=" + eventName + ")");
    }

    totalHandlers = idHandlers.size() + nameHandlers.size();
    if (totalHandlers > 0)
    {
      iora::core::Logger::debug("EventQueue: Worker " + std::to_string(workerId) +
                                " dispatching event (id=" + eventId + ", name=" + eventName +
                                ") to " + std::to_string(totalHandlers) + " handlers");
    }

    const bool idRan = invokeAdmitted(idHandlers, event, "event ID", eventId);
    const bool nameRan = invokeAdmitted(nameHandlers, event, "event name", eventName);
    handled = idRan || nameRan;

    if (!handled)
    {
      iora::core::Logger::debug("EventQueue: No handlers found for event (id=" + eventId +
                                ", name=" + eventName + ") - discarding");
    }
  }

  /// Invokes each admitted handler (exceptions logged and swallowed) and
  /// releases its admission right after it runs. Returns true if any handler
  /// returned normally.
  static bool invokeAdmitted(std::vector<AdmittedHandler> &entries, const parsers::Json &event,
                             const char *what, const std::string &key)
  {
    bool ran = false;
    for (auto &entry : entries)
    {
      try
      {
        entry.second(event);
        ran = true;
      }
      catch (const std::exception &e)
      {
        iora::core::Logger::error(std::string("EventQueue: Handler exception for ") + what + " " +
                                  key + ": " + e.what());
      }
      catch (...)
      {
        iora::core::Logger::error(std::string("EventQueue: Handler threw a non-std::exception for ") +
                                  what + " " + key);
      }
      releaseAdmitted(entry);
    }
    return ran;
  }

  /// Destroys the handler copy while it is still admitted, then releases the
  /// admission, so a drain of its owner waits only for this entry.
  static void releaseAdmitted(AdmittedHandler &entry) noexcept
  {
    entry.second = nullptr;
    entry.first = CallbackGate::Admission{};
  }

  bool eventNameMatches(const std::string &pattern, const std::string &name) const
  {
    if (pattern.find('*') == std::string::npos)
    {
      return pattern == name;
    }

    std::string regexPattern;
    regexPattern.reserve(pattern.size() * 2);
    for (char ch : pattern)
    {
      if (ch == '*')
      {
        regexPattern += ".*";
      }
      else if (std::isalnum(static_cast<unsigned char>(ch)) || ch == ':' || ch == '_')
      {
        regexPattern += ch;
      }
      else
      {
        regexPattern += '\\';
        regexPattern += ch;
      }
    }

    try
    {
      return std::regex_match(name, std::regex(regexPattern));
    }
    catch (...)
    {
      return false;
    }
  }
};
} // namespace core
} // namespace iora