
// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <iostream>
#include <string>
#include <queue>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <regex>

#include "iora/parsers/json.hpp"
#include "iora/core/logger.hpp"

namespace iora
{
namespace core
{

  /// \brief Thread-safe event queue for dispatching JSON events to registered
  /// handlers using worker threads.
  class EventQueue
  {
  public:
    using Handler = std::function<void(const parsers::Json&)>;

    /// \brief Construct the event queue and spin up worker threads
    EventQueue(std::size_t threadCount = std::thread::hardware_concurrency())
    {
      iora::core::Logger::info("EventQueue: Initializing with " +
                               std::to_string(threadCount) + " worker threads");
      for (std::size_t i = 0; i < threadCount; ++i)
      {
        _threads.emplace_back([this, i]() { this->workerLoop(i); });
      }
      iora::core::Logger::info(
          "EventQueue: All worker threads started successfully");
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

      for (auto& thread : _threads)
      {
        if (thread.joinable())
        {
          thread.join();
        }
      }
      iora::core::Logger::debug(
          "EventQueue: All worker threads shut down successfully");
    }

    /// \brief Enqueue an event for processing
    void push(const parsers::Json& event)
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
        iora::core::Logger::debug("EventQueue: Enqueued event (id=" + eventId +
                                  ", name=" + eventName + ") - queue size: " +
                                  std::to_string(_queue.size()));
      }

      _cv.notify_one();
    }

    /// \brief Register a handler for an exact eventId
    void onEventId(const std::string& eventId, Handler handler)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _handlersById[eventId].emplace_back(std::move(handler));
      iora::core::Logger::info(
          "EventQueue: Registered handler for event ID: " + eventId +
          " (total handlers for this ID: " +
          std::to_string(_handlersById[eventId].size()) + ")");
    }

    /// \brief Register a handler for an exact eventName
    void onEventName(const std::string& eventName, Handler handler)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _handlersByName[eventName].emplace_back(std::move(handler));
      iora::core::Logger::info(
          "EventQueue: Registered handler for event name: " + eventName +
          " (total handlers for this name: " +
          std::to_string(_handlersByName[eventName].size()) + ")");
    }

    /// \brief Register a handler for an eventName using regex matching
    void onEventNameMatches(const std::string& eventNamePattern,
                            Handler handler)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      try
      {
        _compiledHandlersByName[eventNamePattern] =
            std::make_pair(std::regex(eventNamePattern), std::move(handler));
        iora::core::Logger::info(
            "EventQueue: Registered pattern handler for event name pattern: " +
            eventNamePattern);
      }
      catch (const std::exception& e)
      {
        iora::core::Logger::error("EventQueue: Failed to register pattern "
                                  "handler for invalid regex: " +
                                  eventNamePattern + " - " + e.what());
        throw;
      }
    }

  private:
    bool isValidEvent(const parsers::Json& event) const
    {
      return event.contains("eventId") && event.contains("eventName");
    }

    std::mutex _mutex;
    std::condition_variable _cv;
    std::queue<parsers::Json> _queue;
    std::map<std::string, std::vector<Handler>> _handlersById;
    std::map<std::string, std::vector<Handler>> _handlersByName;
    std::map<std::string, std::pair<std::regex, Handler>>
        _compiledHandlersByName;
    std::vector<std::thread> _threads;
    bool _shutdown = false;

    void workerLoop(std::size_t workerId)
    {
      iora::core::Logger::debug("EventQueue: Worker thread " +
                                std::to_string(workerId) + " started");
      while (true)
      {
        parsers::Json event;

        {
          std::unique_lock<std::mutex> lock(_mutex);
          _cv.wait(lock, [this]() { return !_queue.empty() || _shutdown; });

          if (_shutdown && _queue.empty())
          {
            iora::core::Logger::debug("EventQueue: Worker thread " +
                                      std::to_string(workerId) +
                                      " shutting down");
            return;
          }

          event = _queue.front();
          _queue.pop();
        }

        dispatch(event, workerId);
      }
    }

    void dispatch(const parsers::Json& event, std::size_t workerId)
    {
      const std::string eventId = event["eventId"];
      const std::string eventName = event["eventName"];

      bool handled = false;
      std::size_t totalHandlers = 0;

      std::vector<Handler> idHandlers;
      std::vector<Handler> nameHandlers;

      {
        std::unique_lock<std::mutex> lock(_mutex);

        auto idHandlersIt = _handlersById.find(eventId);
        if (idHandlersIt != _handlersById.end())
        {
          idHandlers = idHandlersIt->second;
        }

        auto nameHandlersIt = _handlersByName.find(eventName);
        if (nameHandlersIt != _handlersByName.end())
        {
          nameHandlers = nameHandlersIt->second;
        }

        for (const auto& [pattern, compiledHandler] : _compiledHandlersByName)
        {
          if (std::regex_match(eventName, compiledHandler.first))
          {
            nameHandlers.emplace_back(compiledHandler.second);
          }
        }
      }

      totalHandlers = idHandlers.size() + nameHandlers.size();
      if (totalHandlers > 0)
      {
        iora::core::Logger::debug(
            "EventQueue: Worker " + std::to_string(workerId) +
            " dispatching event (id=" + eventId + ", name=" + eventName +
            ") to " + std::to_string(totalHandlers) + " handlers");
      }

      for (const auto& handler : idHandlers)
      {
        try
        {
          handler(event);
          handled = true;
        }
        catch (const std::exception& e)
        {
          iora::core::Logger::error(
              "EventQueue: Handler exception for event ID " + eventId + ": " +
              e.what());
        }
      }

      for (const auto& handler : nameHandlers)
      {
        try
        {
          handler(event);
          handled = true;
        }
        catch (const std::exception& e)
        {
          iora::core::Logger::error(
              "EventQueue: Handler exception for event name " + eventName +
              ": " + e.what());
        }
      }

      if (!handled)
      {
        iora::core::Logger::debug(
            "EventQueue: No handlers found for event (id=" + eventId +
            ", name=" + eventName + ") - discarding");
      }
    }

    bool eventNameMatches(const std::string& pattern,
                          const std::string& name) const
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
        else if (std::isalnum(static_cast<unsigned char>(ch)) || ch == ':' ||
                 ch == '_')
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