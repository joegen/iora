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

#include "iora/core/json.hpp"
#include "iora/core/thread_pool.hpp"

namespace iora {
namespace util {

  /// \brief Thread-safe event queue for dispatching JSON events to registered
  /// handlers using worker threads.
  class EventQueue
  {
  public:
    using Handler = std::function<void(const core::Json&)>;

    /// \brief Construct the event queue and spin up worker threads
    EventQueue(std::size_t threadCount = std::thread::hardware_concurrency())
    {
      for (std::size_t i = 0; i < threadCount; ++i)
      {
        _threads.emplace_back([this]() { this->workerLoop(); });
      }
    }

    /// \brief Destructor gracefully shuts down the worker threads
    ~EventQueue()
    {
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
    }

    /// \brief Enqueue an event for processing
    void push(const core::Json& event)
    {
      if (!isValidEvent(event))
      {
        return; // drop invalid event
      }

      {
        std::unique_lock<std::mutex> lock(_mutex);
        _queue.push(event);
      }

      _cv.notify_one();
    }

    /// \brief Register a handler for an exact eventId
    void onEventId(const std::string& eventId, Handler handler)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _handlersById[eventId].emplace_back(std::move(handler));
    }

    /// \brief Register a handler for an exact eventName
    void onEventName(const std::string& eventName, Handler handler)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _handlersByName[eventName].emplace_back(std::move(handler));
    }

    /// \brief Register a handler for an eventName using regex matching
    void onEventNameMatches(const std::string& eventNamePattern,
                            Handler handler)
    {
      std::unique_lock<std::mutex> lock(_mutex);
      _compiledHandlersByName[eventNamePattern] =
          std::make_pair(std::regex(eventNamePattern), std::move(handler));
    }

  private:
    bool isValidEvent(const core::Json& event) const
    {
      return event.contains("eventId") && event.contains("eventName");
    }

    std::mutex _mutex;
    std::condition_variable _cv;
    std::queue<core::Json> _queue;
    std::map<std::string, std::vector<Handler>> _handlersById;
    std::map<std::string, std::vector<Handler>> _handlersByName;
    std::map<std::string, std::pair<std::regex, Handler>>
        _compiledHandlersByName;
    std::vector<std::thread> _threads;
    bool _shutdown = false;

    void workerLoop()
    {
      while (true)
      {
        core::Json event;

        {
          std::unique_lock<std::mutex> lock(_mutex);
          _cv.wait(lock, [this]() { return !_queue.empty() || _shutdown; });

          if (_shutdown && _queue.empty())
          {
            return;
          }

          event = _queue.front();
          _queue.pop();
        }

        dispatch(event);
      }
    }

    void dispatch(const core::Json& event)
    {
      const std::string eventId = event["eventId"];
      const std::string eventName = event["eventName"];

      bool handled = false;

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

      for (const auto& handler : idHandlers)
      {
        handler(event);
        handled = true;
      }

      for (const auto& handler : nameHandlers)
      {
        handler(event);
        handled = true;
      }

      if (!handled)
      {
        // silently discard
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
} } // namespace iora::util