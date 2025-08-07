#pragma once

#include <nlohmann/json.hpp>
namespace iora {
namespace core
{
  /// JSON type alias to avoid exposing third-party namespaces.
  using Json = nlohmann::json;
} } // namespace iora:: core