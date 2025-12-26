// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0

/// \file ip_utils.hpp
/// \brief IP address utilities for parsing, validation, and CIDR matching
///
/// Provides:
/// - IPv4 and IPv6 address parsing and validation
/// - CIDR notation parsing for both address families
/// - Network matching (is IP in CIDR range)
/// - Trusted network list management with dual-stack support

#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <variant>
#include <vector>

namespace iora
{
namespace network
{

/// \brief IPv4 address parsing and manipulation utilities
class IPv4
{
public:
  /// \brief Parse IPv4 address string to 32-bit integer
  /// \param ip IPv4 address string (e.g., "192.168.1.1")
  /// \param result Output 32-bit integer in host byte order
  /// \return true if parsed successfully
  /// \note Rejects leading zeros to prevent octal interpretation ambiguity
  static bool parse(const std::string& ip, std::uint32_t& result)
  {
    if (ip.empty())
    {
      return false;
    }

    std::array<std::uint32_t, 4> octets{};
    std::size_t pos = 0;

    for (std::size_t i = 0; i < 4; ++i)
    {
      if (i > 0)
      {
        if (pos >= ip.length() || ip[pos] != '.')
        {
          return false;
        }
        ++pos;
      }

      // Parse octet - reject leading zeros (security: prevents octal ambiguity)
      if (pos >= ip.length() || !std::isdigit(static_cast<unsigned char>(ip[pos])))
      {
        return false;
      }

      std::size_t octetStart = pos;
      std::uint32_t octet = 0;

      while (pos < ip.length() && std::isdigit(static_cast<unsigned char>(ip[pos])))
      {
        octet = octet * 10 + static_cast<std::uint32_t>(ip[pos] - '0');
        if (octet > 255)
        {
          return false;
        }
        ++pos;
      }

      // Reject leading zeros (e.g., "01", "001") - security measure
      // Only "0" itself is allowed, not "00" or "01"
      std::size_t octetLen = pos - octetStart;
      if (octetLen > 1 && ip[octetStart] == '0')
      {
        return false;
      }

      octets[i] = octet;
    }

    // Check for trailing characters
    if (pos != ip.length())
    {
      return false;
    }

    result = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return true;
  }

  /// \brief Convert 32-bit integer to IPv4 string
  /// \param ip 32-bit IP in host byte order
  /// \return Dotted decimal string
  static std::string toString(std::uint32_t ip)
  {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
  }

  /// \brief Create netmask from CIDR prefix length
  /// \param prefixLength CIDR prefix (0-32)
  /// \return 32-bit netmask in host byte order
  static std::uint32_t prefixToNetmask(std::uint32_t prefixLength)
  {
    if (prefixLength == 0)
    {
      return 0;
    }
    if (prefixLength >= 32)
    {
      return 0xFFFFFFFF;
    }
    return ~((1u << (32 - prefixLength)) - 1);
  }

  /// \brief Check if IP address is within a network
  /// \param ip IP address to check (32-bit)
  /// \param network Network address (32-bit)
  /// \param prefixLength CIDR prefix length
  /// \return true if IP is within the network
  static bool inNetwork(
    std::uint32_t ip,
    std::uint32_t network,
    std::uint32_t prefixLength)
  {
    std::uint32_t mask = prefixToNetmask(prefixLength);
    return (ip & mask) == (network & mask);
  }

  /// \brief Check if IP string is within a network
  /// \param ipStr IP address string
  /// \param networkStr Network address string
  /// \param prefixLength CIDR prefix length
  /// \return true if IP is within the network
  static bool inNetwork(
    const std::string& ipStr,
    const std::string& networkStr,
    std::uint32_t prefixLength)
  {
    std::uint32_t ip = 0;
    std::uint32_t network = 0;

    if (!parse(ipStr, ip) || !parse(networkStr, network))
    {
      return false;
    }

    return inNetwork(ip, network, prefixLength);
  }

  /// \brief Validate IPv4 address format
  /// \param ip Address string to validate
  /// \return true if valid IPv4 format
  static bool isValid(const std::string& ip)
  {
    std::uint32_t dummy = 0;
    return parse(ip, dummy);
  }

  /// \brief Check if address is a private/RFC1918 address
  /// \param ip 32-bit IP in host byte order
  /// \return true if private address
  static bool isPrivate(std::uint32_t ip)
  {
    // 10.0.0.0/8
    if ((ip & 0xFF000000) == 0x0A000000)
    {
      return true;
    }
    // 172.16.0.0/12
    if ((ip & 0xFFF00000) == 0xAC100000)
    {
      return true;
    }
    // 192.168.0.0/16
    if ((ip & 0xFFFF0000) == 0xC0A80000)
    {
      return true;
    }
    return false;
  }

  /// \brief Check if address is a loopback address (127.0.0.0/8)
  static bool isLoopback(std::uint32_t ip)
  {
    return (ip & 0xFF000000) == 0x7F000000;
  }

  /// \brief Check if address string is private
  static bool isPrivate(const std::string& ipStr)
  {
    std::uint32_t ip = 0;
    if (!parse(ipStr, ip))
    {
      return false;
    }
    return isPrivate(ip);
  }
};

/// \brief IPv6 address parsing and manipulation utilities
class IPv6
{
public:
  /// \brief 128-bit IPv6 address represented as array of 16 bytes
  using Address = std::array<std::uint8_t, 16>;

  /// \brief Parse IPv6 address string to 128-bit byte array
  /// \param ip IPv6 address string (e.g., "2001:db8::1", "::1")
  /// \param result Output 128-bit address
  /// \return true if parsed successfully
  static bool parse(const std::string& ip, Address& result)
  {
    result.fill(0);

    if (ip.empty())
    {
      return false;
    }

    // Check for IPv4-mapped IPv6 (::ffff:192.168.1.1) - case insensitive
    if (ip.length() > 7 && ip[0] == ':' && ip[1] == ':')
    {
      // Check for "ffff:" prefix (case insensitive)
      std::string prefix = ip.substr(2, 5);
      bool isV4Mapped = (prefix.length() == 5 &&
        (prefix[0] == 'f' || prefix[0] == 'F') &&
        (prefix[1] == 'f' || prefix[1] == 'F') &&
        (prefix[2] == 'f' || prefix[2] == 'F') &&
        (prefix[3] == 'f' || prefix[3] == 'F') &&
        prefix[4] == ':');

      if (isV4Mapped)
      {
        std::uint32_t ipv4 = 0;
        if (IPv4::parse(ip.substr(7), ipv4))
        {
          // Set IPv4-mapped prefix
          result[10] = 0xff;
          result[11] = 0xff;
          result[12] = static_cast<std::uint8_t>((ipv4 >> 24) & 0xFF);
          result[13] = static_cast<std::uint8_t>((ipv4 >> 16) & 0xFF);
          result[14] = static_cast<std::uint8_t>((ipv4 >> 8) & 0xFF);
          result[15] = static_cast<std::uint8_t>(ipv4 & 0xFF);
          return true;
        }
      }
    }

    // Parse standard IPv6 format
    std::vector<std::uint16_t> groups;
    std::size_t doubleColonPos = std::string::npos;
    std::size_t start = 0;
    bool seenDoubleColon = false;

    // Handle leading ::
    if (ip.length() >= 2 && ip[0] == ':' && ip[1] == ':')
    {
      seenDoubleColon = true;
      doubleColonPos = 0;
      start = 2;
      if (ip.length() == 2)
      {
        // Just "::" - all zeros
        return true;
      }
    }

    std::size_t pos = start;
    while (pos < ip.length())
    {
      // Find end of current group
      std::size_t colonPos = ip.find(':', pos);

      // Check for double colon
      if (colonPos != std::string::npos && colonPos + 1 < ip.length() && ip[colonPos + 1] == ':')
      {
        if (seenDoubleColon)
        {
          return false; // Multiple :: not allowed
        }
        seenDoubleColon = true;

        if (colonPos > pos)
        {
          // Parse group before ::
          std::string group = ip.substr(pos, colonPos - pos);
          if (!parseGroup(group, groups))
          {
            return false;
          }
        }
        // Set doubleColonPos AFTER adding the group before ::
        doubleColonPos = groups.size();
        pos = colonPos + 2;
        continue;
      }

      std::string group;
      if (colonPos == std::string::npos)
      {
        group = ip.substr(pos);
        pos = ip.length();
      }
      else
      {
        group = ip.substr(pos, colonPos - pos);
        pos = colonPos + 1;
      }

      if (!group.empty())
      {
        if (!parseGroup(group, groups))
        {
          return false;
        }
      }
    }

    // Validate group count
    if (seenDoubleColon)
    {
      if (groups.size() > 7)
      {
        return false;
      }
    }
    else
    {
      if (groups.size() != 8)
      {
        return false;
      }
    }

    // Fill result array
    if (seenDoubleColon)
    {
      std::size_t zerosNeeded = 8 - groups.size();
      std::size_t resultIdx = 0;

      // Groups before ::
      for (std::size_t i = 0; i < doubleColonPos && i < groups.size(); ++i)
      {
        result[resultIdx * 2] = static_cast<std::uint8_t>((groups[i] >> 8) & 0xFF);
        result[resultIdx * 2 + 1] = static_cast<std::uint8_t>(groups[i] & 0xFF);
        ++resultIdx;
      }

      // Skip zeros
      resultIdx += zerosNeeded;

      // Groups after ::
      for (std::size_t i = doubleColonPos; i < groups.size(); ++i)
      {
        result[resultIdx * 2] = static_cast<std::uint8_t>((groups[i] >> 8) & 0xFF);
        result[resultIdx * 2 + 1] = static_cast<std::uint8_t>(groups[i] & 0xFF);
        ++resultIdx;
      }
    }
    else
    {
      for (std::size_t i = 0; i < 8; ++i)
      {
        result[i * 2] = static_cast<std::uint8_t>((groups[i] >> 8) & 0xFF);
        result[i * 2 + 1] = static_cast<std::uint8_t>(groups[i] & 0xFF);
      }
    }

    return true;
  }

  /// \brief Convert 128-bit address to IPv6 string (compressed form)
  /// \param addr 128-bit address
  /// \return Compressed IPv6 string (RFC 5952 compliant)
  static std::string toString(const Address& addr)
  {
    // Extract 8 groups
    std::array<std::uint16_t, 8> groups{};
    for (std::size_t i = 0; i < 8; ++i)
    {
      groups[i] = (static_cast<std::uint16_t>(addr[i * 2]) << 8) | addr[i * 2 + 1];
    }

    // Find longest run of zeros for compression (must be > 1 to compress)
    std::size_t bestStart = 8;  // 8 means "no compression"
    std::size_t bestLen = 1;    // Only compress runs > 1
    std::size_t curStart = 0;
    std::size_t curLen = 0;

    for (std::size_t i = 0; i < 8; ++i)
    {
      if (groups[i] == 0)
      {
        if (curLen == 0)
        {
          curStart = i;
        }
        ++curLen;
        if (curLen > bestLen)
        {
          bestStart = curStart;
          bestLen = curLen;
        }
      }
      else
      {
        curLen = 0;
      }
    }

    // Build output string using simple two-pass approach
    std::ostringstream oss;
    oss << std::hex;
    bool emittedDoubleColon = false;

    for (std::size_t i = 0; i < 8; ++i)
    {
      // Skip groups that are part of the zero run to compress
      if (bestStart < 8 && i >= bestStart && i < bestStart + bestLen)
      {
        if (!emittedDoubleColon)
        {
          oss << "::";
          emittedDoubleColon = true;
        }
        continue;
      }

      // Add colon separator (but not before first group or right after ::)
      if (i > 0 && !emittedDoubleColon)
      {
        oss << ":";
      }
      emittedDoubleColon = false;

      oss << groups[i];
    }

    return oss.str();
  }

  /// \brief Check if IP address is within a network
  /// \param ip IP address to check
  /// \param network Network address
  /// \param prefixLength CIDR prefix length (0-128)
  /// \return true if IP is within the network
  static bool inNetwork(
    const Address& ip,
    const Address& network,
    std::uint32_t prefixLength)
  {
    if (prefixLength > 128)
    {
      prefixLength = 128;
    }

    std::size_t fullBytes = prefixLength / 8;
    std::size_t remainingBits = prefixLength % 8;

    // Compare full bytes
    for (std::size_t i = 0; i < fullBytes; ++i)
    {
      if (ip[i] != network[i])
      {
        return false;
      }
    }

    // Compare remaining bits
    if (remainingBits > 0 && fullBytes < 16)
    {
      std::uint8_t mask = static_cast<std::uint8_t>(0xFF << (8 - remainingBits));
      if ((ip[fullBytes] & mask) != (network[fullBytes] & mask))
      {
        return false;
      }
    }

    return true;
  }

  /// \brief Check if IP string is within a network
  static bool inNetwork(
    const std::string& ipStr,
    const std::string& networkStr,
    std::uint32_t prefixLength)
  {
    Address ip{};
    Address network{};

    if (!parse(ipStr, ip) || !parse(networkStr, network))
    {
      return false;
    }

    return inNetwork(ip, network, prefixLength);
  }

  /// \brief Validate IPv6 address format
  /// \param ip Address string to validate
  /// \return true if valid IPv6 format
  static bool isValid(const std::string& ip)
  {
    Address dummy{};
    return parse(ip, dummy);
  }

  /// \brief Check if address is loopback (::1)
  static bool isLoopback(const Address& addr)
  {
    Address loopback{};
    loopback[15] = 1;
    return addr == loopback;
  }

  /// \brief Check if address is link-local (fe80::/10)
  static bool isLinkLocal(const Address& addr)
  {
    return (addr[0] == 0xfe) && ((addr[1] & 0xc0) == 0x80);
  }

  /// \brief Check if address is unique local address (fc00::/7 - RFC 4193)
  static bool isUniqueLocal(const Address& addr)
  {
    return (addr[0] & 0xfe) == 0xfc;
  }

  /// \brief Check if address is IPv4-mapped (::ffff:0:0/96)
  static bool isIPv4Mapped(const Address& addr)
  {
    for (std::size_t i = 0; i < 10; ++i)
    {
      if (addr[i] != 0)
      {
        return false;
      }
    }
    return addr[10] == 0xff && addr[11] == 0xff;
  }

private:
  static bool parseGroup(const std::string& group, std::vector<std::uint16_t>& groups)
  {
    if (group.empty() || group.length() > 4)
    {
      return false;
    }

    for (char c : group)
    {
      if (!std::isxdigit(static_cast<unsigned char>(c)))
      {
        return false;
      }
    }

    try
    {
      std::uint32_t val = static_cast<std::uint32_t>(std::stoul(group, nullptr, 16));
      if (val > 0xFFFF)
      {
        return false;
      }
      groups.push_back(static_cast<std::uint16_t>(val));
      return true;
    }
    catch (const std::invalid_argument&)
    {
      return false;
    }
    catch (const std::out_of_range&)
    {
      return false;
    }
  }
};

/// \brief Address family enumeration
enum class AddressFamily
{
  IPv4,
  IPv6
};

/// \brief Unified IP address that can hold IPv4 or IPv6
class IpAddress
{
public:
  IpAddress() = default;

  /// \brief Construct from string (auto-detects family)
  explicit IpAddress(const std::string& addr)
  {
    parse(addr);
  }

  /// \brief Parse address string (auto-detects IPv4 vs IPv6)
  /// \return true if parsed successfully
  bool parse(const std::string& addr)
  {
    _original = addr;

    // Try IPv4 first (simpler format)
    std::uint32_t ipv4 = 0;
    if (IPv4::parse(addr, ipv4))
    {
      _family = AddressFamily::IPv4;
      _ipv4 = ipv4;
      _valid = true;
      return true;
    }

    // Try IPv6
    IPv6::Address ipv6{};
    if (IPv6::parse(addr, ipv6))
    {
      _family = AddressFamily::IPv6;
      _ipv6 = ipv6;
      _valid = true;
      return true;
    }

    _valid = false;
    return false;
  }

  /// \brief Check if address is valid
  bool isValid() const { return _valid; }

  /// \brief Get address family
  AddressFamily family() const { return _family; }

  /// \brief Get IPv4 address (only valid if family is IPv4)
  std::uint32_t ipv4() const { return _ipv4; }

  /// \brief Get IPv6 address (only valid if family is IPv6)
  const IPv6::Address& ipv6() const { return _ipv6; }

  /// \brief Get original string representation
  const std::string& original() const { return _original; }

  /// \brief Convert to string
  std::string toString() const
  {
    if (!_valid)
    {
      return "";
    }
    if (_family == AddressFamily::IPv4)
    {
      return IPv4::toString(_ipv4);
    }
    return IPv6::toString(_ipv6);
  }

  /// \brief Check if address is in network
  bool inNetwork(const IpAddress& network, std::uint32_t prefixLength) const
  {
    if (!_valid || !network._valid || _family != network._family)
    {
      return false;
    }

    if (_family == AddressFamily::IPv4)
    {
      return IPv4::inNetwork(_ipv4, network._ipv4, prefixLength);
    }
    return IPv6::inNetwork(_ipv6, network._ipv6, prefixLength);
  }

private:
  AddressFamily _family{AddressFamily::IPv4};
  std::uint32_t _ipv4{0};
  IPv6::Address _ipv6{};
  std::string _original;
  bool _valid{false};
};

/// \brief Detect if an IP string is IPv6
inline bool isIPv6Address(const std::string& ip)
{
  return ip.find(':') != std::string::npos;
}

/// \brief Validate any IP address (IPv4 or IPv6)
inline bool isValidIpAddress(const std::string& ip)
{
  if (isIPv6Address(ip))
  {
    return IPv6::isValid(ip);
  }
  return IPv4::isValid(ip);
}

/// \brief CIDR network representation (supports both IPv4 and IPv6)
struct CidrNetwork
{
  std::string address;                     ///< Network address
  std::uint32_t prefixLength{32};          ///< CIDR prefix (0-32 for IPv4, 0-128 for IPv6)
  std::uint32_t addressNum{0};             ///< Parsed IPv4 address as 32-bit int
  IPv6::Address addressV6{};               ///< Parsed IPv6 address as 128-bit array
  AddressFamily family{AddressFamily::IPv4}; ///< Address family
  bool valid{false};                       ///< True if address was parsed successfully

  CidrNetwork() = default;

  /// \brief Construct from address and prefix
  /// \note Check isValid() after construction to verify parsing succeeded
  CidrNetwork(const std::string& addr, std::uint32_t prefix)
    : address(addr), prefixLength(prefix)
  {
    if (isIPv6Address(addr))
    {
      family = AddressFamily::IPv6;
      valid = IPv6::parse(addr, addressV6);
      // Validate prefix for IPv6
      if (valid && prefixLength > 128)
      {
        valid = false;
      }
    }
    else
    {
      family = AddressFamily::IPv4;
      valid = IPv4::parse(addr, addressNum);
      // Validate prefix for IPv4
      if (valid && prefixLength > 32)
      {
        valid = false;
      }
    }
  }

  /// \brief Check if the network was parsed/constructed successfully
  bool isValid() const { return valid; }

  /// \brief Parse CIDR notation string
  /// \param cidr CIDR string (e.g., "192.168.1.0/24", "10.0.0.1", "2001:db8::/32")
  /// \return true if parsed successfully
  bool parse(const std::string& cidr)
  {
    auto slashPos = cidr.find('/');
    std::string addrPart;

    if (slashPos == std::string::npos)
    {
      addrPart = cidr;
    }
    else
    {
      addrPart = cidr.substr(0, slashPos);
      try
      {
        // Use stoul to avoid negative value issues
        unsigned long prefix = std::stoul(cidr.substr(slashPos + 1));
        if (prefix > 128)  // Max valid prefix for either family
        {
          return false;
        }
        prefixLength = static_cast<std::uint32_t>(prefix);
      }
      catch (const std::invalid_argument&)
      {
        return false;
      }
      catch (const std::out_of_range&)
      {
        return false;
      }
    }

    // Detect address family and validate
    if (isIPv6Address(addrPart))
    {
      family = AddressFamily::IPv6;
      if (!IPv6::parse(addrPart, addressV6))
      {
        return false;
      }

      // Set default prefix for IPv6 if not specified
      if (slashPos == std::string::npos)
      {
        prefixLength = 128;  // Single IP
      }
      else if (prefixLength > 128)
      {
        return false;  // Invalid prefix for IPv6
      }

      address = addrPart;
      valid = true;
      return true;
    }
    else
    {
      family = AddressFamily::IPv4;
      if (!IPv4::parse(addrPart, addressNum))
      {
        return false;
      }

      // Set default prefix for IPv4 if not specified
      if (slashPos == std::string::npos)
      {
        prefixLength = 32;  // Single IP
      }
      else if (prefixLength > 32)
      {
        return false;  // Invalid prefix for IPv4
      }

      address = addrPart;
      valid = true;
      return true;
    }
  }

  /// \brief Convert to CIDR notation string
  std::string toString() const
  {
    std::uint32_t maxPrefix = (family == AddressFamily::IPv6) ? 128 : 32;
    if (prefixLength == maxPrefix)
    {
      return address;
    }
    return address + "/" + std::to_string(prefixLength);
  }

  /// \brief Check if an IP is within this network
  bool contains(const std::string& ip) const
  {
    // Determine family of input IP
    if (isIPv6Address(ip))
    {
      if (family != AddressFamily::IPv6)
      {
        return false;  // Family mismatch
      }
      IPv6::Address ipV6{};
      if (!IPv6::parse(ip, ipV6))
      {
        return false;
      }
      return IPv6::inNetwork(ipV6, addressV6, prefixLength);
    }
    else
    {
      if (family != AddressFamily::IPv4)
      {
        return false;  // Family mismatch
      }
      std::uint32_t ipNum = 0;
      if (!IPv4::parse(ip, ipNum))
      {
        return false;
      }
      return IPv4::inNetwork(ipNum, addressNum, prefixLength);
    }
  }

  /// \brief Check if an IPv4 (32-bit) is within this network
  bool contains(std::uint32_t ip) const
  {
    if (family != AddressFamily::IPv4)
    {
      return false;
    }
    return IPv4::inNetwork(ip, addressNum, prefixLength);
  }

  /// \brief Check if an IPv6 address is within this network
  bool contains(const IPv6::Address& ip) const
  {
    if (family != AddressFamily::IPv6)
    {
      return false;
    }
    return IPv6::inNetwork(ip, addressV6, prefixLength);
  }

  /// \brief Check if this is a single IP (not a range)
  bool isSingleHost() const
  {
    if (family == AddressFamily::IPv6)
    {
      return prefixLength == 128;
    }
    return prefixLength == 32;
  }

  /// \brief Check if this network is IPv6
  bool isIPv6() const
  {
    return family == AddressFamily::IPv6;
  }
};

/// \brief Trusted network entry with metadata
struct TrustedNetworkEntry
{
  std::string id;                          ///< Unique identifier
  CidrNetwork network;                     ///< The network/IP
  std::string description;                 ///< Optional description
  bool enabled{true};                      ///< Whether entry is active

  /// \brief Parse from CIDR string
  bool parse(const std::string& cidr)
  {
    return network.parse(cidr);
  }

  /// \brief Get CIDR string representation
  std::string toString() const
  {
    return network.toString();
  }
};

/// \brief Thread-safe trusted network list with efficient lookup
///
/// Optimizes for the common case of checking if an IP is trusted:
/// - Single IPs stored in hash set for O(1) lookup
/// - CIDR ranges checked sequentially (typically few entries)
class TrustedNetworkList
{
public:
  TrustedNetworkList() = default;

  /// \brief Add a trusted network entry
  /// \param entry TrustedNetworkEntry to add
  /// \return true if added (false if duplicate)
  bool add(const TrustedNetworkEntry& entry)
  {
    std::unique_lock lock(_mutex);

    // Check for duplicate
    for (const auto& e : _entries)
    {
      if (e.network.address == entry.network.address &&
          e.network.prefixLength == entry.network.prefixLength)
      {
        return false;
      }
    }

    TrustedNetworkEntry newEntry = entry;
    if (newEntry.id.empty())
    {
      newEntry.id = generateId();
    }

    _entries.push_back(newEntry);
    rebuildIndex();
    return true;
  }

  /// \brief Add trusted network from CIDR string
  /// \param cidr CIDR notation (e.g., "192.168.1.0/24")
  /// \param description Optional description
  /// \return ID of added entry, or empty if failed
  std::string addCidr(const std::string& cidr, const std::string& description = "")
  {
    TrustedNetworkEntry entry;
    if (!entry.parse(cidr))
    {
      return "";
    }
    entry.description = description;

    std::unique_lock lock(_mutex);

    // Check for duplicate
    for (const auto& e : _entries)
    {
      if (e.network.address == entry.network.address &&
          e.network.prefixLength == entry.network.prefixLength)
      {
        return "";
      }
    }

    entry.id = generateId();
    _entries.push_back(entry);
    rebuildIndex();
    return entry.id;
  }

  /// \brief Remove entry by ID
  /// \return true if removed
  bool removeById(const std::string& id)
  {
    std::unique_lock lock(_mutex);

    auto it = std::remove_if(_entries.begin(), _entries.end(),
      [&id](const TrustedNetworkEntry& e) { return e.id == id; });

    if (it != _entries.end())
    {
      _entries.erase(it, _entries.end());
      rebuildIndex();
      return true;
    }
    return false;
  }

  /// \brief Remove entry by CIDR address
  /// \return true if removed
  bool removeByCidr(const std::string& cidr)
  {
    CidrNetwork net;
    if (!net.parse(cidr))
    {
      return false;
    }

    std::unique_lock lock(_mutex);

    auto it = std::remove_if(_entries.begin(), _entries.end(),
      [&net](const TrustedNetworkEntry& e) {
        return e.network.address == net.address &&
               e.network.prefixLength == net.prefixLength;
      });

    if (it != _entries.end())
    {
      _entries.erase(it, _entries.end());
      rebuildIndex();
      return true;
    }
    return false;
  }

  /// \brief Check if an IP is trusted (supports both IPv4 and IPv6)
  /// \param ip IP address string
  /// \return true if matches any enabled trusted network
  bool contains(const std::string& ip) const
  {
    std::shared_lock lock(_mutex);

    // Fast path: exact match for single IPs
    if (_singleIpSet.count(ip) > 0)
    {
      return true;
    }

    // Determine if input is IPv4 or IPv6
    bool isV6 = isIPv6Address(ip);

    // Slow path: CIDR ranges (check by family)
    if (isV6)
    {
      IPv6::Address ipV6{};
      if (!IPv6::parse(ip, ipV6))
      {
        return false;
      }

      for (const auto& cidr : _cidrRangesV6)
      {
        if (cidr.enabled && cidr.network.contains(ipV6))
        {
          return true;
        }
      }
    }
    else
    {
      std::uint32_t ipNum = 0;
      if (!IPv4::parse(ip, ipNum))
      {
        return false;
      }

      for (const auto& cidr : _cidrRanges)
      {
        if (cidr.enabled && cidr.network.contains(ipNum))
        {
          return true;
        }
      }
    }

    return false;
  }

  /// \brief Get all entries
  std::vector<TrustedNetworkEntry> getAll() const
  {
    std::shared_lock lock(_mutex);
    return _entries;
  }

  /// \brief Get entry by ID
  std::optional<TrustedNetworkEntry> getById(const std::string& id) const
  {
    std::shared_lock lock(_mutex);
    for (const auto& e : _entries)
    {
      if (e.id == id)
      {
        return e;
      }
    }
    return std::nullopt;
  }

  /// \brief Get count of entries
  std::size_t size() const
  {
    std::shared_lock lock(_mutex);
    return _entries.size();
  }

  /// \brief Clear all entries
  void clear()
  {
    std::unique_lock lock(_mutex);
    _entries.clear();
    _singleIpSet.clear();
    _cidrRanges.clear();
    _cidrRangesV6.clear();
  }

  /// \brief Enable/disable entry by ID
  bool setEnabled(const std::string& id, bool enabled)
  {
    std::unique_lock lock(_mutex);
    for (auto& e : _entries)
    {
      if (e.id == id)
      {
        e.enabled = enabled;
        rebuildIndex();
        return true;
      }
    }
    return false;
  }

private:
  void rebuildIndex()
  {
    _singleIpSet.clear();
    _cidrRanges.clear();
    _cidrRangesV6.clear();

    for (const auto& entry : _entries)
    {
      if (!entry.enabled)
      {
        continue;
      }

      if (entry.network.isSingleHost())
      {
        // Single IPs go to hash set for O(1) lookup (works for both IPv4 and IPv6)
        _singleIpSet.insert(entry.network.address);
      }
      else
      {
        // CIDR ranges are separated by family for efficient matching
        if (entry.network.isIPv6())
        {
          _cidrRangesV6.push_back(entry);
        }
        else
        {
          _cidrRanges.push_back(entry);
        }
      }
    }
  }

  std::string generateId()
  {
    // Use atomic fetch_add for thread-safe ID generation
    return "net_" + std::to_string(_idCounter.fetch_add(1, std::memory_order_relaxed) + 1);
  }

  mutable std::shared_mutex _mutex;
  std::vector<TrustedNetworkEntry> _entries;
  std::unordered_set<std::string> _singleIpSet;  // Fast lookup for /32 and /128
  std::vector<TrustedNetworkEntry> _cidrRanges;  // IPv4 CIDR ranges to check
  std::vector<TrustedNetworkEntry> _cidrRangesV6; // IPv6 CIDR ranges to check
  std::atomic<std::uint64_t> _idCounter{0};      // Atomic for thread-safe ID generation
};

} // namespace network
} // namespace iora
