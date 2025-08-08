// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <nlohmann/json.hpp>
namespace iora {
namespace core
{
  /// JSON type alias to avoid exposing third-party namespaces.
  using Json = nlohmann::json;
} } // namespace iora:: core