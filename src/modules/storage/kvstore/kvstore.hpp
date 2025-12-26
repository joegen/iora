// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

/// \file kvstore.hpp
/// \brief Backward compatibility header - redirects to iora/storage/kvstore.hpp
///
/// This header is kept for backward compatibility with existing code that includes
/// "kvstore.hpp" directly. New code should include <iora/storage/kvstore.hpp> instead.

#pragma once

#include "iora/storage/kvstore.hpp"

// Backward compatibility aliases in global namespace
using KVStoreConfig = iora::storage::KVStoreConfig;
using KVStoreException = iora::storage::KVStoreException;
using KVStore = iora::storage::KVStore;

// Constants also need aliases for backward compatibility
static constexpr size_t MAX_KEY_LENGTH = iora::storage::MAX_KEY_LENGTH;
static constexpr size_t MAX_VALUE_LENGTH = iora::storage::MAX_VALUE_LENGTH;
