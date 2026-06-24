// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

/// @file errno_utils.hpp
/// @brief Thread-safe errno -> message conversion.

#include <cstring>
#include <string>

namespace iora {
namespace core {

/// \brief Convert an errno value to its message string, thread-safely.
///
/// Bare std::strerror / strerror are MT-Unsafe (they return a pointer into a
/// process-global static buffer; concurrent calls race). This wraps strerror_r
/// correctly for BOTH variants:
///  - GNU glibc (only when _GNU_SOURCE is in effect): strerror_r returns a char*
///    that MAY be a static string and MAY leave buf untouched — the result MUST
///    be taken from the return value, never from buf (an untouched buf has no
///    NUL terminator, so std::string(buf) runs strlen off the end -> heap
///    corruption).
///  - XSI/POSIX (macOS, glibc without _GNU_SOURCE): strerror_r returns int
///    (0 on success) and always writes into buf.
/// The selection is gated on _GNU_SOURCE (not merely __GLIBC__), so the helper
/// is correct whether or not the GNU extension is enabled.
inline std::string errnoMessage(int errnoVal)
{
  char buf[256] = {0};
#if defined(__GLIBC__) && defined(_GNU_SOURCE) && !defined(__APPLE__)
  // GNU variant: char* return is the message (may be static, may be buf).
  return std::string(::strerror_r(errnoVal, buf, sizeof(buf)));
#else
  // XSI variant: int return, message written into buf.
  const int rc = ::strerror_r(errnoVal, buf, sizeof(buf));
  if (rc == 0)
  {
    return std::string(buf);
  }
  // rc != 0 (e.g. EINVAL/ERANGE): buf may hold a truncated message; fall back to
  // a deterministic string rather than reading a possibly-unterminated buffer.
  return "Unknown error " + std::to_string(errnoVal);
#endif
}

} // namespace core
} // namespace iora
