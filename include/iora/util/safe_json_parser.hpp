// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once
#include <iostream>
#include <stdexcept>
#include <string>

#include "iora/core/json.hpp"

namespace iora {
namespace util {
    
  /// \brief Safe JSON parsing with size limits and validation
  class SafeJsonParser
  {
  public:
    static constexpr size_t MAX_JSON_SIZE = 10 * 1024 * 1024; // 10MB limit
    static constexpr size_t MAX_JSON_DEPTH = 100;             // Depth limit

    static core::Json parseWithLimits(const std::string& input)
    {
      if (input.size() > MAX_JSON_SIZE)
      {
        throw std::runtime_error("JSON payload exceeds maximum size limit of " +
                                 std::to_string(MAX_JSON_SIZE) + " bytes");
      }

      if (input.empty())
      {
        return core::Json::object();
      }

      try
      {
        auto parsed = core::Json::parse(input);
        validateJsonDepth(parsed, 0);
        return parsed;
      }
      catch (const core::Json::parse_error& e)
      {
        throw std::runtime_error("JSON parse error: " + std::string(e.what()));
      }
    }

  private:
    static void validateJsonDepth(const core::Json& j, size_t depth)
    {
      if (depth > MAX_JSON_DEPTH)
      {
        throw std::runtime_error("JSON depth exceeds maximum limit of " +
                                 std::to_string(MAX_JSON_DEPTH));
      }

      if (j.is_object())
      {
        for (const auto& [key, value] : j.items())
        {
          validateJsonDepth(value, depth + 1);
        }
      }
      else if (j.is_array())
      {
        for (const auto& item : j)
        {
          validateJsonDepth(item, depth + 1);
        }
      }
    }
  };

} } // namespace iora::util