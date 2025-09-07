// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <algorithm>
#include <cctype>
#include <string>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief Normalize server string for consistent DNS key creation and comparison
///
/// Handles IPv6, IPv4, and hostname normalization according to these rules:
/// - IPv6 with brackets: [2001:DB8::1] → [2001:db8::1]
/// - IPv6 with zone: [2001:DB8::1%Eth0] → [2001:db8::1%Eth0] (zone case preserved)
/// - Bare IPv6: 2001:DB8::1 → 2001:db8::1
/// - IPv4: 192.168.1.1 → 192.168.1.1 (unchanged)
/// - Hostnames: DNS.Google.COM → dns.google.com (case-insensitive)
/// - Whitespace is always trimmed from both ends
///
/// IMPORTANT: External callers must use consistent formatting:
/// - Always use bracket notation for IPv6 in mixed environments
/// - Zone IDs are case-sensitive (interface names)
/// - DNS names are case-insensitive per RFC 1035
///
/// \param server Server address string (IPv4, IPv6, hostname)
/// \return Canonicalized server string for consistent matching
inline std::string normalizeServerString(const std::string &server)
{
  std::string normalized = server;

  // Trim whitespace
  size_t start = normalized.find_first_not_of(" \t\n\r");
  if (start == std::string::npos)
    return ""; // All whitespace

  size_t end = normalized.find_last_not_of(" \t\n\r");
  normalized = normalized.substr(start, end - start + 1);

  // Handle IPv6 address canonicalization
  if (normalized.front() == '[' && normalized.back() == ']')
  {
    // IPv6 bracket notation: [2001:db8::1] or [2001:db8::1%eth0]
    std::string ipv6_part = normalized.substr(1, normalized.length() - 2);

    // Handle zone ID (scope) - keep it but normalize case
    size_t zone_pos = ipv6_part.find('%');
    if (zone_pos != std::string::npos)
    {
      std::string addr_part = ipv6_part.substr(0, zone_pos);
      std::string zone_part = ipv6_part.substr(zone_pos + 1);

      // Convert address part to lowercase, keep zone case-sensitive (may be interface name)
      std::transform(addr_part.begin(), addr_part.end(), addr_part.begin(), ::tolower);
      return "[" + addr_part + "%" + zone_part + "]";
    }
    else
    {
      // No zone ID, just normalize IPv6 address to lowercase
      std::transform(ipv6_part.begin(), ipv6_part.end(), ipv6_part.begin(), ::tolower);
      return "[" + ipv6_part + "]";
    }
  }
  else if (normalized.find(':') != std::string::npos && normalized.find('.') == std::string::npos)
  {
    // Bare IPv6 address without brackets: 2001:db8::1 or 2001:db8::1%eth0
    // Note: This is ambiguous with hostnames containing colons, but rare in practice
    size_t zone_pos = normalized.find('%');
    if (zone_pos != std::string::npos)
    {
      std::string addr_part = normalized.substr(0, zone_pos);
      std::string zone_part = normalized.substr(zone_pos + 1);

      // Convert address part to lowercase, keep zone case-sensitive
      std::transform(addr_part.begin(), addr_part.end(), addr_part.begin(), ::tolower);
      return addr_part + "%" + zone_part;
    }
    else
    {
      // No zone ID, normalize to lowercase
      std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
      return normalized;
    }
  }
  else
  {
    // IPv4 address or hostname handling
    bool hasLetters = false;
    for (char c : normalized)
    {
      if (std::isalpha(c))
      {
        hasLetters = true;
        break;
      }
    }

    if (hasLetters)
    {
      // Hostname - convert to lowercase for DNS case-insensitivity
      std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);
    }
    // IPv4 addresses are kept as-is (case doesn't matter for digits/dots)
  }

  return normalized;
}

} // namespace dns
} // namespace network
} // namespace iora