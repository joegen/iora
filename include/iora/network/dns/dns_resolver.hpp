// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include "dns_cache.hpp"
#include "dns_transport.hpp"
#include "dns_types.hpp"
#include "iora/core/string_utils.hpp"
#include <algorithm>
#include <cctype>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <vector>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief Service transport type for NAPTR record filtering
/// Supports SIP and other service discovery protocols following RFC 3263
enum class ServiceType
{
  SIPS_TLS,  ///< SIPS over TLS (secure)
  SIPS_SCTP, ///< SIPS over SCTP (secure)
  SIPS_WSS,  ///< SIPS over WSS (secure WebSocket)
  SIP_TCP,   ///< SIP over TCP
  SIP_UDP,   ///< SIP over UDP
  SIP_SCTP,  ///< SIP over SCTP
  SIP_WS,    ///< SIP over WebSocket
  HTTP_TCP,  ///< HTTP over TCP (for generic HTTP service discovery)
  HTTPS_TCP, ///< HTTPS over TCP (secure HTTP)
  Unknown    ///< Unknown or unsupported service
};

/// \brief Resolved service target with all connection details
struct ServiceTarget
{
  std::string hostname;               ///< Target hostname
  std::uint16_t port;                 ///< Target port
  ServiceType transport;              ///< Transport protocol
  std::uint16_t priority;             ///< SRV priority (lower = higher priority)
  std::uint16_t weight;               ///< SRV weight for load balancing
  std::uint16_t naptrPreference{0};   ///< NAPTR preference (RFC 3403 §4.1) — lower = preferred.
                                      ///< 0 = no NAPTR tier (direct SRV/A fallback path).
  std::vector<std::string> addresses; ///< Resolved IP addresses (A/AAAA)

  /// \brief Get transport protocol as string
  std::string getTransportString() const
  {
    switch (transport)
    {
    case ServiceType::SIPS_TLS:
      return "tls";
    case ServiceType::SIP_TCP:
      return "tcp";
    case ServiceType::SIP_UDP:
      return "udp";
    case ServiceType::SIP_SCTP:
      return "sctp";
    case ServiceType::SIPS_SCTP:
      return "sctp";
    case ServiceType::SIPS_WSS:
      return "wss";
    case ServiceType::SIP_WS:
      return "ws";
    case ServiceType::HTTP_TCP:
      return "tcp";
    case ServiceType::HTTPS_TCP:
      return "tls";
    default:
      return "unknown";
    }
  }

  /// \brief Check if this is a secure transport
  bool isSecure() const
  {
    return transport == ServiceType::SIPS_TLS || transport == ServiceType::SIPS_SCTP ||
           transport == ServiceType::SIPS_WSS || transport == ServiceType::HTTPS_TCP;
  }
};

/// \brief NAPTR 'S' flag target — SRV domain name for SRV resolution
/// Carries NAPTR preference so SRV results preserve NAPTR transport ordering
struct NaptrSrvTarget
{
  ServiceType service{ServiceType::Unknown};
  std::string srvName;
  std::uint16_t naptrPreference{0};
};

/// \brief NAPTR 'A' flag target — hostname for direct A/AAAA resolution (no SRV)
/// Carries NAPTR order/preference for correct priority ordering (RFC 3403 §4.1)
struct NaptrDirectTarget
{
  ServiceType service{ServiceType::Unknown};
  std::string hostname;
  std::uint16_t order{0};
  std::uint16_t preference{0};
};

/// \brief Service resolution result with prioritized targets
/// Follows RFC 3263 NAPTR→SRV→A/AAAA resolution chain
struct ServiceResolutionResult
{
  std::vector<ServiceTarget> targets;              ///< Resolved targets (priority sorted)
  std::string domain;                              ///< Original domain queried
  bool fromCache{false};                           ///< Whether result came from cache
  std::chrono::steady_clock::time_point timestamp; ///< Resolution timestamp

  /// \brief Constructor
  explicit ServiceResolutionResult(const std::string &d = "")
      : domain(d), timestamp(std::chrono::steady_clock::now())
  {
  }

  /// \brief Check if resolution was successful
  bool isSuccess() const { return !targets.empty(); }

  /// \brief Get targets for specific transport
  /// \param transport Desired transport type
  /// \return Filtered targets
  std::vector<ServiceTarget> getTargetsForTransport(ServiceType transport) const
  {
    std::vector<ServiceTarget> filtered;
    for (const auto &target : targets)
    {
      if (target.transport == transport)
      {
        filtered.push_back(target);
      }
    }
    return filtered;
  }

  /// \brief Get preferred target with DETERMINISTIC weighted selection
  ///
  /// IMPORTANT: This const overload uses a deterministic RNG seeded from candidate targets.
  /// This provides consistent, reproducible selection for the same set of targets,
  /// which is useful for testing and debugging. However, it does NOT provide proper
  /// load distribution in production environments.
  ///
  /// For production randomness with proper load balancing, use:
  /// - getPreferredTarget(RNG&) with your own RNG
  /// - getPreferredTargetWithDefaultRng() for thread-local randomness
  ///
  /// \return Selected target using deterministic weighted selection
  ServiceTarget getPreferredTarget() const
  {
    if (targets.empty())
    {
      return ServiceTarget{};
    }

    // First: find the best (lowest) NAPTR preference tier
    std::uint16_t bestNaptrPref = targets[0].naptrPreference;
    for (const auto &target : targets)
    {
      if (target.naptrPreference < bestNaptrPref)
      {
        bestNaptrPref = target.naptrPreference;
      }
    }

    // Second: within that NAPTR tier, find best (lowest) SRV priority
    std::uint16_t best_priority = std::numeric_limits<std::uint16_t>::max();
    for (const auto &target : targets)
    {
      if (target.naptrPreference == bestNaptrPref && target.priority < best_priority)
      {
        best_priority = target.priority;
      }
    }

    // Third: collect candidates matching both naptrPreference and SRV priority
    std::vector<ServiceTarget> candidates;
    for (const auto &target : targets)
    {
      if (target.naptrPreference == bestNaptrPref && target.priority == best_priority)
      {
        candidates.push_back(target);
      }
    }

    // If only one candidate, return it
    if (candidates.size() == 1)
    {
      return candidates[0];
    }

    // Weight-based selection among equal priority targets
    std::uint32_t total_weight = 0;
    for (const auto &candidate : candidates)
    {
      total_weight += candidate.weight;
    }

    if (total_weight == 0)
    {
      // All weights are 0, use deterministic RNG seeded from targets for consistent selection
      std::mt19937 deterministicRng;
      std::size_t seed = std::hash<std::size_t>{}(candidates.size());
      for (const auto &candidate : candidates)
      {
        seed ^=
          std::hash<std::string>{}(candidate.hostname) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        seed ^= std::hash<std::uint16_t>{}(candidate.port) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
      }
      deterministicRng.seed(static_cast<std::uint32_t>(seed));

      std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
      return candidates[dist(deterministicRng)];
    }

    // RFC 2782 weighted selection with deterministic RNG seeded from candidates
    std::mt19937 deterministicRng;
    std::size_t seed = std::hash<std::uint32_t>{}(total_weight);
    for (const auto &candidate : candidates)
    {
      seed ^= std::hash<std::string>{}(candidate.hostname) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
      seed ^= std::hash<std::uint16_t>{}(candidate.port) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
      seed ^= std::hash<std::uint16_t>{}(candidate.weight) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
    deterministicRng.seed(static_cast<std::uint32_t>(seed));

    // Use the same weighted random logic as the RNG overload
    std::uniform_int_distribution<std::uint32_t> dist(0, total_weight - 1);
    std::uint32_t random_weight = dist(deterministicRng);

    std::uint32_t cumulative_weight = 0;
    for (const auto &candidate : candidates)
    {
      cumulative_weight += candidate.weight;
      if (random_weight < cumulative_weight)
      {
        return candidate;
      }
    }

    // Fallback (should never reach here)
    return candidates.back();
  }

  /// \brief Get preferred target with PRODUCTION-GRADE random weighted selection
  ///
  /// This method uses thread-local random number generation for proper load balancing
  /// in production environments. Each thread maintains its own RNG state seeded from
  /// std::random_device, providing excellent distribution across multiple targets.
  ///
  /// \return Selected target using thread-local randomness (production recommended)
  ServiceTarget getPreferredTargetWithDefaultRng() const
  {
    // Thread-local RNG for production randomness without coordination overhead
    thread_local std::mt19937 productionRng(std::random_device{}());
    return getPreferredTarget(productionRng);
  }

  /// \brief Get preferred target with RFC 2782 compliant weighted random selection
  /// \param rng Random number generator for weighted selection
  /// \return Selected target based on priority and weighted randomness
  template <typename RNG> ServiceTarget getPreferredTarget(RNG &rng) const
  {
    if (targets.empty())
    {
      return ServiceTarget{};
    }

    // First: find the best (lowest) NAPTR preference tier
    std::uint16_t bestNaptrPref = targets[0].naptrPreference;
    for (const auto &target : targets)
    {
      if (target.naptrPreference < bestNaptrPref)
      {
        bestNaptrPref = target.naptrPreference;
      }
    }

    // Second: within that NAPTR tier, find best (lowest) SRV priority
    std::uint16_t best_priority = std::numeric_limits<std::uint16_t>::max();
    for (const auto &target : targets)
    {
      if (target.naptrPreference == bestNaptrPref && target.priority < best_priority)
      {
        best_priority = target.priority;
      }
    }

    // Third: collect candidates matching both naptrPreference and SRV priority
    std::vector<ServiceTarget> candidates;
    for (const auto &target : targets)
    {
      if (target.naptrPreference == bestNaptrPref && target.priority == best_priority)
      {
        candidates.push_back(target);
      }
    }

    // If only one candidate, return it
    if (candidates.size() == 1)
    {
      return candidates[0];
    }

    // RFC 2782 weighted random selection among equal priority targets
    std::uint32_t total_weight = 0;
    for (const auto &candidate : candidates)
    {
      total_weight += candidate.weight;
    }

    if (total_weight == 0)
    {
      // All weights are 0, choose randomly among candidates
      std::uniform_int_distribution<size_t> dist(0, candidates.size() - 1);
      return candidates[dist(rng)];
    }

    // Weighted random selection (RFC 2782)
    std::uniform_int_distribution<std::uint32_t> dist(0, total_weight - 1);
    std::uint32_t random_weight = dist(rng);

    std::uint32_t cumulative_weight = 0;
    for (const auto &candidate : candidates)
    {
      cumulative_weight += candidate.weight;
      if (random_weight < cumulative_weight)
      {
        return candidate;
      }
    }

    // Should never reach here, but return last candidate as fallback
    return candidates.back();
  }
};

/// \brief DNS resolver exception hierarchy
class DnsResolverException : public std::exception
{
public:
  explicit DnsResolverException(const std::string &message,
                                DnsResponseCode code = DnsResponseCode::SERVFAIL)
      : message_(message), responseCode_(code)
  {
  }

  const char *what() const noexcept override { return message_.c_str(); }

  DnsResponseCode getResponseCode() const noexcept { return responseCode_; }

private:
  std::string message_;
  DnsResponseCode responseCode_;
};

class DnsResolutionFailedException : public DnsResolverException
{
public:
  explicit DnsResolutionFailedException(const std::string &domain, DnsResponseCode code)
      : DnsResolverException("Failed to resolve domain: " + domain, code)
  {
  }
};

class DnsNoRecordsException : public DnsResolverException
{
public:
  explicit DnsNoRecordsException(const std::string &domain, DnsType type)
      : DnsResolverException("No " + typeToString(type) + " records found for: " + domain,
                             DnsResponseCode::NXDOMAIN)
  {
  }

private:
  std::string typeToString(DnsType type) const
  {
    switch (type)
    {
    case DnsType::A:
      return "A";
    case DnsType::AAAA:
      return "AAAA";
    case DnsType::SRV:
      return "SRV";
    case DnsType::NAPTR:
      return "NAPTR";
    case DnsType::CNAME:
      return "CNAME";
    case DnsType::MX:
      return "MX";
    case DnsType::TXT:
      return "TXT";
    case DnsType::PTR:
      return "PTR";
    default:
      return "Unknown";
    }
  }
};

/// \brief High-level DNS resolver with SIP-aware logic
///
/// This resolver implements the complete RFC 3263 service discovery chain:
/// 1. NAPTR query to find supported services and their preferences
/// 2. SRV query for each discovered service to get targets and priorities
/// 3. A/AAAA queries to resolve hostnames to IP addresses
/// 4. Intelligent caching and fallback mechanisms
/// Supports SIP, HTTP, and other service discovery protocols.
class DnsResolver : public std::enable_shared_from_this<DnsResolver>
{
public:
  /// \brief Service resolution callback for async operations
  using ServiceResolutionCallback =
    std::function<void(const ServiceResolutionResult &, const std::exception_ptr &)>;

  /// \brief Simple DNS query callback (uses DnsTransport::QueryCallback)
  using QueryCallback = DnsTransport::QueryCallback;

  /// \brief Constructor
  /// \param transport DNS transport layer
  /// \param cache DNS cache (optional)
  /// \param config DNS configuration
  explicit DnsResolver(std::shared_ptr<DnsTransport> transport,
                       std::shared_ptr<DnsCache> cache = nullptr,
                       const DnsConfig &config = DnsConfig{})
      : transport_(transport), cache_(cache), config_(config)
  {
    // Initialize RNG with random seed for production use
    std::random_device rd;
    rng_.seed(rd());
  }

  /// \brief Set RNG seed for deterministic testing
  /// \param seed Seed value for reproducible randomness
  void setRngSeed(std::uint32_t seed)
  {
    std::lock_guard<std::mutex> lock(rngMutex_);
    rng_.seed(seed);
  }

  /// \brief Resolve service domain using RFC 3263 NAPTR→SRV→A/AAAA procedure
  /// \param domain Service domain to resolve (e.g., "example.com", "sip.example.com")
  /// \param preferredTransports Preferred transport types in order of preference
  /// \return Service resolution result with prioritized targets
  /// \throws DnsResolverException on resolution failure
  ServiceResolutionResult
  resolveServiceDomain(const std::string &domain,
                       const std::vector<ServiceType> &preferredTransports = {})
  {
    // Validate input domain
    if (!validateHostname(domain))
    {
      throw DnsResolverException("Invalid hostname: " + sanitizeInput(domain, 100));
    }

    // Check cache first
    if (cache_)
    {
      DnsQuestion naptrQuestion(domain, DnsType::NAPTR, DnsClass::IN);
      DnsResult naptrResult;
      if (cache_->get(naptrQuestion, naptrResult))
      {
        iora::core::Logger::debug("DNS service resolution cache hit for domain: " + domain);
        ServiceResolutionResult result(domain);
        result.fromCache = true;
        processCachedServiceResolution(result, naptrResult, preferredTransports);
        if (result.isSuccess())
        {
          return result;
        }
        else
        {
          iora::core::Logger::debug("DNS cached service resolution incomplete for domain: " +
                                    domain);
        }
      }
      else
      {
        iora::core::Logger::debug("DNS service resolution cache miss for domain: " + domain);
      }
    }

    // Perform fresh resolution
    iora::core::Logger::debug("DNS starting fresh service resolution for domain: " + domain);
    auto startTime = std::chrono::steady_clock::now();

    auto result = performServiceResolution(domain, preferredTransports);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - startTime)
                      .count();

    iora::core::Logger::info("DNS fresh service resolution completed for domain: " + domain +
                             " duration=" + std::to_string(duration) + "ms" +
                             " targets=" + std::to_string(result.targets.size()) +
                             " success=" + (result.isSuccess() ? "true" : "false"));

    return result;
  }

  /// \brief Resolve service domain asynchronously using NAPTR→SRV→A/AAAA chain
  /// \param domain Service domain to resolve
  /// \param callback Callback function for result notification
  /// \param preferredTransports Preferred transport types in order of preference
  void resolveServiceDomainAsync(const std::string &domain, ServiceResolutionCallback callback,
                                 const std::vector<ServiceType> &preferredTransports = {})
  {
    // Check cache first
    if (cache_)
    {
      DnsQuestion naptrQuestion(domain, DnsType::NAPTR, DnsClass::IN);
      DnsResult naptrResult;
      if (cache_->get(naptrQuestion, naptrResult))
      {
        iora::core::Logger::debug("DNS async service resolution cache hit for domain: " + domain);
        try
        {
          ServiceResolutionResult result(domain);
          result.fromCache = true;
          processCachedServiceResolution(result, naptrResult, preferredTransports);
          if (result.isSuccess())
          {
            callback(result, nullptr);
            return;
          }
          else
          {
            iora::core::Logger::debug(
              "DNS cached async service resolution incomplete for domain: " + domain);
          }
        }
        catch (...)
        {
          iora::core::Logger::debug("DNS cached async service resolution error for domain: " +
                                    domain);
          // Fall through to fresh resolution
        }
      }
      else
      {
        iora::core::Logger::debug("DNS async service resolution cache miss for domain: " + domain);
      }
    }

    // Perform async fresh resolution
    iora::core::Logger::debug("DNS starting async fresh service resolution for domain: " + domain);
    auto startTime =
      std::make_shared<std::chrono::steady_clock::time_point>(std::chrono::steady_clock::now());

    performServiceResolutionAsync(
      domain,
      [domain, startTime, callback](const ServiceResolutionResult &result, std::exception_ptr error)
      {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - *startTime)
                          .count();

        if (error)
        {
          iora::core::Logger::info("DNS async fresh service resolution failed for domain: " +
                                   domain + " duration=" + std::to_string(duration) + "ms");
        }
        else
        {
          iora::core::Logger::info("DNS async fresh service resolution completed for domain: " +
                                   domain + " duration=" + std::to_string(duration) + "ms" +
                                   " targets=" + std::to_string(result.targets.size()) +
                                   " success=" + (result.isSuccess() ? "true" : "false"));
        }

        callback(result, error);
      },
      preferredTransports);
  }

  /// \brief Perform standard DNS query
  /// \param question DNS question to resolve
  /// \return DNS query result
  /// \throws DnsResolverException on query failure
  DnsResult query(const DnsQuestion &question)
  {
    // Check cache first
    if (cache_)
    {
      DnsResult result;
      if (cache_->get(question, result))
      {
        // For negative cache hits, still need to throw the appropriate exception
        if (!result.isSuccess())
        {
          throw DnsResolutionFailedException(question.qname, result.header.rcode);
        }
        return result;
      }
    }

    // Perform query via transport
    DnsResult result = transport_->query(question);

    cacheQueryResult(question, result);

    if (!result.isSuccess())
    {
      throw DnsResolutionFailedException(question.qname, result.header.rcode);
    }

    return result;
  }

  /// \brief Perform DNS query asynchronously
  /// \param question DNS question to resolve
  /// \param callback Callback function for result
  void queryAsync(const DnsQuestion &question, QueryCallback callback)
  {
    // Check cache first
    if (cache_)
    {
      DnsResult result;
      if (cache_->get(question, result))
      {
        // For negative cache hits, still need to pass the appropriate exception
        if (!result.isSuccess())
        {
          auto dns_ex = std::make_exception_ptr(
            DnsResolutionFailedException(question.qname, result.header.rcode));
          callback(result, dns_ex);
          return;
        }
        callback(result, nullptr);
        return;
      }
    }

    // Perform async query
    auto self = shared_from_this();
    transport_->queryAsync(
      question,
      [self, question, callback](const DnsResult &result, const std::exception_ptr &ex)
      {
        if (ex)
        {
          callback(result, ex);
          return;
        }

        self->cacheQueryResult(question, result);

        if (!result.isSuccess())
        {
          auto dns_ex = std::make_exception_ptr(
            DnsResolutionFailedException(question.qname, result.header.rcode));
          callback(result, dns_ex);
          return;
        }

        callback(result, nullptr);
      });
  }

  /// \brief Resolve hostname to IP addresses
  /// \param hostname Hostname to resolve
  /// \param prefer_ipv6 Prefer IPv6 addresses if available
  /// \return Vector of IP address strings
  /// \throws DnsResolverException on resolution failure
  std::vector<std::string> resolveHostname(const std::string &hostname, bool prefer_ipv6 = false)
  {
    // Validate input hostname
    if (!validateHostname(hostname))
    {
      throw DnsResolverException("Invalid hostname: " + sanitizeInput(hostname, 100));
    }

    // Determine address resolution policy
    // If prefer_ipv6 is explicitly set, honor it for backward compatibility
    AddressResolutionPolicy policy = config_.addressResolutionPolicy;
    if (prefer_ipv6 && policy == AddressResolutionPolicy::IPv4First)
    {
      policy = AddressResolutionPolicy::IPv6First;
    }

    std::vector<std::string> ipv4Addresses;
    std::vector<std::string> ipv6Addresses;

    try
    {
      // Query A records (IPv4) if policy allows
      if (policy == AddressResolutionPolicy::IPv4Only ||
          policy == AddressResolutionPolicy::IPv4First ||
          policy == AddressResolutionPolicy::IPv6First)
      {
        try
        {
          DnsResult ipv4Result = query(DnsQuestion(hostname, DnsType::A, DnsClass::IN));
          for (const auto &record : ipv4Result.a_records)
          {
            ipv4Addresses.push_back(record.address);
          }
        }
        catch (const DnsResolverException &)
        {
          // IPv4 query failed, continue
        }
      }

      // Query AAAA records (IPv6) if policy allows
      if (policy == AddressResolutionPolicy::IPv6Only ||
          policy == AddressResolutionPolicy::IPv4First ||
          policy == AddressResolutionPolicy::IPv6First)
      {
        try
        {
          DnsResult ipv6Result = query(DnsQuestion(hostname, DnsType::AAAA, DnsClass::IN));
          for (const auto &record : ipv6Result.aaaa_records)
          {
            ipv6Addresses.push_back(record.address);
          }
        }
        catch (const DnsResolverException &)
        {
          // IPv6 query failed, continue
        }
      }

      // Combine results according to policy
      std::vector<std::string> addresses;

      switch (policy)
      {
      case AddressResolutionPolicy::IPv4Only:
        addresses = std::move(ipv4Addresses);
        break;

      case AddressResolutionPolicy::IPv6Only:
        addresses = std::move(ipv6Addresses);
        break;

      case AddressResolutionPolicy::IPv4First:
        // IPv4 addresses first, then IPv6
        addresses.reserve(ipv4Addresses.size() + ipv6Addresses.size());
        addresses.insert(addresses.end(), ipv4Addresses.begin(), ipv4Addresses.end());
        addresses.insert(addresses.end(), ipv6Addresses.begin(), ipv6Addresses.end());
        break;

      case AddressResolutionPolicy::IPv6First:
        // IPv6 addresses first, then IPv4
        addresses.reserve(ipv6Addresses.size() + ipv4Addresses.size());
        addresses.insert(addresses.end(), ipv6Addresses.begin(), ipv6Addresses.end());
        addresses.insert(addresses.end(), ipv4Addresses.begin(), ipv4Addresses.end());
        break;
      }

      // If no addresses found, throw exception
      if (addresses.empty())
      {
        throw DnsNoRecordsException(
          hostname, policy == AddressResolutionPolicy::IPv6Only ? DnsType::AAAA : DnsType::A);
      }

      return addresses;
    }
    catch (const DnsResolverException &)
    {
      // If both queries failed, throw appropriate exception
      DnsType failedType =
        (policy == AddressResolutionPolicy::IPv6Only) ? DnsType::AAAA : DnsType::A;
      throw DnsNoRecordsException(hostname, failedType);
    }
  }

  /// \brief Get preferred target from resolution result using resolver's RNG
  ///
  /// This method provides access to RFC-compliant weighted random target selection
  /// using the resolver's internal RNG, which is essential for deterministic testing
  /// when a seed has been set via setRngSeed().
  ///
  /// \param result Service resolution result containing prioritized targets
  /// \return Selected target based on priority and weighted randomness
  ServiceTarget getPreferredTarget(const ServiceResolutionResult &result) const
  {
    // rng_ is mutated (the generator advances) even on this const path; guard it
    // so concurrent getPreferredTarget()/setRngSeed() calls don't race the state.
    std::lock_guard<std::mutex> lock(rngMutex_);
    return result.getPreferredTarget(rng_);
  }

  /// \brief Handle direct SRV resolution when no NAPTR records exist (generic version)
  /// \param domain Domain to resolve
  /// \param preferredTransports Preferred transport types
  /// \param srvQueries Custom SRV queries to perform (defaults to SIP services for backward
  /// compatibility)
  /// \return Service resolution result
  ServiceResolutionResult performDirectSrvResolution(
    const std::string &domain, const std::vector<ServiceType> &preferredTransports,
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries =
      std::nullopt)
  {
    ServiceResolutionResult result(domain);

    auto actualSrvQueries = buildOrderedSrvQueries(domain, srvQueries, preferredTransports);

    // Query SRV records. Track which services returned an RFC 2782 "." abort so the
    // A/AAAA fallback is suppressed per-service (not domain-wide).
    std::vector<ServiceType> deniedServices;
    for (const auto &[srvName, service] : actualSrvQueries)
    {
      try
      {
        DnsResult srvResult = query(DnsQuestion(srvName, DnsType::SRV, DnsClass::IN));
        if (processSrvRecords(srvResult.srv_records, service, result))
        {
          deniedServices.push_back(service);
        }
      }
      catch (const DnsResolverException &)
      {
        // Skip failed queries
        continue;
      }
    }

    if (!result.targets.empty())
    {
      resolveTargetAddresses(result);
      sortTargetsByPriority(result);
    }
    else
    {
      // No SRV targets: fall back to A/AAAA on the domain for the transports that
      // were NOT explicitly declared unavailable by an SRV "." (RFC 2782).
      performFallbackResolution(domain, result, preferredTransports, deniedServices);
    }

    return result;
  }

  /// \brief Perform direct SRV resolution asynchronously (generic version)
  /// \param domain Domain to resolve
  /// \param callback Result callback
  /// \param preferredTransports Preferred transport types
  /// \param srvQueries Custom SRV queries to perform (defaults to SIP services for backward
  /// compatibility)
  void performDirectSrvResolutionAsync(
    const std::string &domain, ServiceResolutionCallback callback,
    const std::vector<ServiceType> &preferredTransports,
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries =
      std::nullopt)
  {
    auto actualSrvQueries = buildOrderedSrvQueries(domain, srvQueries, preferredTransports);

    auto result = std::make_shared<ServiceResolutionResult>(domain);

    // Zero-work guard: with no SRV queries to issue, the per-query completion block
    // below never runs, so the user callback would never fire (caller hangs). Mirror
    // the sync path and fall back directly.
    if (actualSrvQueries.empty())
    {
      performFallbackResolutionAsync(domain, result, callback, preferredTransports, {});
      return;
    }

    auto remainingQueries = std::make_shared<std::atomic<size_t>>(actualSrvQueries.size());
    // callbackFired ensures the completion callback is invoked exactly once
    auto callbackFired = std::make_shared<std::atomic<bool>>(false);
    // Mutex protects concurrent writes to result->targets AND deniedServices from
    // parallel SRV callbacks.
    auto resultMutex = std::make_shared<std::mutex>();
    // Services whose SRV query returned an RFC 2782 "." abort; the A/AAAA fallback
    // is suppressed per-service (not domain-wide), mirroring the sync path.
    auto deniedServices = std::make_shared<std::vector<ServiceType>>();

    for (const auto &[srvName, service] : actualSrvQueries)
    {
      DnsQuestion srvQuestion(srvName, DnsType::SRV, DnsClass::IN);

      auto self = shared_from_this();
      transport_->queryAsync(
        srvQuestion,
        [self, result, service, remainingQueries, callbackFired, resultMutex, deniedServices,
         callback, domain, preferredTransports](const DnsResult &srvResult,
                                                 const std::exception_ptr &srvError)
        {
          if (!srvError)
          {
            try
            {
              std::lock_guard<std::mutex> lock(*resultMutex);
              if (self->processSrvRecords(srvResult.srv_records, service, *result))
              {
                deniedServices->push_back(service);
              }
            }
            catch (...)
            {
              // Ignore individual SRV processing errors
            }
          }

          // Completion: the last query to decrement to zero runs the join. acq_rel
          // publishes every prior callback's locked writes (targets/deniedServices)
          // to this thread (concurrency.md HR-1: minimal sufficient ordering).
          if (remainingQueries->fetch_sub(1, std::memory_order_acq_rel) == 1 &&
              !callbackFired->exchange(true))
          {
            if (!result->targets.empty())
            {
              self->resolveTargetAddressesAsync(result, callback);
            }
            else
            {
              // No SRV targets: fall back to A/AAAA for the transports NOT declared
              // unavailable by an SRV "." (RFC 2782). If every fallback transport is
              // denied, performFallbackResolutionAsync yields an empty result and
              // still fires the callback exactly once.
              self->performFallbackResolutionAsync(domain, result, callback, preferredTransports,
                                                   *deniedServices);
            }
          }
        });
    }
  }

private:
  std::shared_ptr<DnsTransport> transport_; ///< DNS transport layer
  std::shared_ptr<DnsCache> cache_;         ///< DNS cache (optional)
  DnsConfig config_;                        ///< DNS configuration

  /// \brief Centralized random number generator for deterministic testing
  mutable std::mt19937 rng_;    ///< Weighted SRV selection RNG (guarded by rngMutex_)
  mutable std::mutex rngMutex_; ///< Guards rng_ against concurrent advance/seed

  // =============================================================================
  // Input Validation Functions (RFC Compliance & Security)
  // =============================================================================

  /// \brief Validate hostname according to RFC 1035
  /// \param hostname Hostname to validate
  /// \return true if valid, false otherwise
  bool validateHostname(const std::string &hostname, bool allowUnderscore = false) const
  {
    if (hostname.empty() || hostname.length() > 255)
    {
      return false; // RFC 1035: max 255 chars
    }

    if (hostname.front() == '.')
    {
      return false; // Leading dot not allowed
    }

    // Handle FQDN (trailing dot indicates fully qualified domain name)
    std::string normalizedHostname = hostname;
    if (normalizedHostname.back() == '.')
    {
      normalizedHostname.pop_back(); // Remove trailing dot for validation

      // Empty after removing trailing dot is invalid
      if (normalizedHostname.empty())
      {
        return false;
      }
    }

    // Check labels (separated by dots) using normalized hostname
    std::size_t labelStart = 0;
    for (std::size_t i = 0; i <= normalizedHostname.length(); ++i)
    {
      if (i == normalizedHostname.length() || normalizedHostname[i] == '.')
      {
        std::size_t labelLen = i - labelStart;
        if (labelLen == 0 || labelLen > 63)
        {
          return false; // RFC 1035: max 63 chars per label, no empty labels
        }

        // Validate label characters
        for (std::size_t j = labelStart; j < i; ++j)
        {
          char c = normalizedHostname[j];
          // Alphanumeric and hyphen always; underscore only when allowed (SRV
          // owner names, RFC 2782 _service._proto, used as NAPTR 'S' replacements).
          if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' &&
              !(allowUnderscore && c == '_'))
          {
            return false;
          }
          if ((j == labelStart || j == i - 1) && c == '-')
          {
            return false; // Hyphen not allowed at start/end of label
          }
        }

        labelStart = i + 1;
      }
    }

    return true;
  }

  /// \brief Validate NAPTR service field according to RFC 3403
  /// \param service NAPTR service string
  /// \return true if valid, false otherwise
  bool validateNaptrService(const std::string &service) const
  {
    if (service.empty() || service.length() > 255)
    {
      return false; // Reasonable length limit
    }

    // Check for valid SIP/WebSocket service patterns (case-insensitive,
    // locale-independent ASCII)
    std::string upper = iora::core::StringUtils::toUpper(service);
    if (upper == "SIPS+D2T" || upper == "SIPS+D2S" || upper == "SIPS+D2W" ||
        upper == "SIP+D2T" || upper == "SIP+D2U" || upper == "SIP+D2S" ||
        upper == "SIP+D2W")
    {
      return true; // Known good SIP services
    }

    // Basic format validation: should be alphanumeric with +, -, _
    for (char c : service)
    {
      if (!std::isalnum(static_cast<unsigned char>(c)) && c != '+' && c != '-' && c != '_')
      {
        return false; // Invalid character
      }
    }

    return true;
  }

  /// \brief Validate NAPTR replacement field as hostname
  /// \param replacement NAPTR replacement string
  /// \return true if valid, false otherwise
  bool validateNaptrReplacement(const std::string &replacement) const
  {
    if (replacement == ".")
    {
      return true; // Terminal replacement
    }

    // A NAPTR 'S'-flag replacement is an SRV owner name (RFC 2782 _service._proto)
    // whose labels legitimately begin with '_'; allow underscores here.
    return validateHostname(replacement, /*allowUnderscore=*/true);
  }

  /// \brief Sanitize and validate input string
  /// \param input Input string to validate
  /// \param maxLength Maximum allowed length
  /// \return Sanitized string or empty if invalid
  std::string sanitizeInput(const std::string &input, std::size_t maxLength = 255) const
  {
    if (input.length() > maxLength)
    {
      return ""; // Reject oversized input
    }

    std::string sanitized;
    sanitized.reserve(input.length());

    for (char c : input)
    {
      // Allow printable ASCII characters only
      if (c >= 32 && c <= 126)
      {
        sanitized.push_back(c);
      }
      // Convert to space for safety
      else if (std::isspace(static_cast<unsigned char>(c)))
      {
        sanitized.push_back(' ');
      }
      // Skip other characters
    }

    return sanitized;
  }

  /// \brief Parse service type from NAPTR service field (iora-level, includes HTTP)
  /// Returns ServiceType::Unknown for unrecognized strings — callers must filter.
  /// Note: SipDnsAdapter::parseNaptrService() is the SIP-specific parallel that returns
  /// std::optional<SipTransportProtocol> and excludes HTTP types.
  /// \param service NAPTR service string (e.g., "SIP+D2U", "SIPS+D2T", "HTTP+D2T")
  /// \return Parsed service type (Unknown for unrecognized strings)
  ServiceType parseServiceType(const std::string &service) const
  {
    // Validate service string first
    if (!validateNaptrService(service))
    {
      return ServiceType::Unknown;
    }

    // Normalize to uppercase for case-insensitive matching (RFC 3403,
    // locale-independent ASCII)
    std::string upper = iora::core::StringUtils::toUpper(service);

    // SIP service mappings
    if (upper == "SIPS+D2T")
      return ServiceType::SIPS_TLS;
    if (upper == "SIPS+D2S")
      return ServiceType::SIPS_SCTP;
    if (upper == "SIPS+D2W")
      return ServiceType::SIPS_WSS;
    if (upper == "SIP+D2T")
      return ServiceType::SIP_TCP;
    if (upper == "SIP+D2U")
      return ServiceType::SIP_UDP;
    if (upper == "SIP+D2S")
      return ServiceType::SIP_SCTP;
    if (upper == "SIP+D2W")
      return ServiceType::SIP_WS;

    // HTTP service mappings
    if (upper == "HTTP+D2T")
      return ServiceType::HTTP_TCP;
    if (upper == "HTTPS+D2T")
      return ServiceType::HTTPS_TCP;

    return ServiceType::Unknown;
  }

  /// \brief Get default port for service type
  /// \param service Service type
  /// \return Default port number
  std::uint16_t getDefaultServicePort(ServiceType service) const
  {
    switch (service)
    {
    case ServiceType::SIPS_TLS:
      return 5061;
    case ServiceType::SIPS_SCTP:
      return 5061;
    case ServiceType::SIPS_WSS:
      return 443;
    case ServiceType::SIP_TCP:
      return 5060;
    case ServiceType::SIP_UDP:
      return 5060;
    case ServiceType::SIP_SCTP:
      return 5060;
    case ServiceType::SIP_WS:
      return 80;
    case ServiceType::HTTP_TCP:
      return 80;
    case ServiceType::HTTPS_TCP:
      return 443;
    default:
      return 5060; // Default to SIP
    }
  }

  /// \brief Perform complete service resolution (NAPTR -> SRV -> A/AAAA)
  /// \param domain Domain to resolve
  /// \param preferredTransports Preferred transport types
  /// \return Service resolution result
  ServiceResolutionResult
  performServiceResolution(const std::string &domain,
                           const std::vector<ServiceType> &preferredTransports)
  {
    ServiceResolutionResult result(domain);

    // Step 1: Query NAPTR records
    std::vector<NaptrRecord> naptrRecords;
    try
    {
      DnsResult naptrResult = query(DnsQuestion(domain, DnsType::NAPTR, DnsClass::IN));
      naptrRecords = naptrResult.naptr_records;
    }
    catch (const DnsResolverException &)
    {
      // No NAPTR records, try direct SRV queries
      return performDirectSrvResolution(domain, preferredTransports, std::nullopt);
    }

    // Step 2: Process NAPTR records to get SRV and direct-A targets
    std::vector<NaptrSrvTarget> srvTargets;
    std::vector<NaptrDirectTarget> aTargets;
    processNaptrRecords(naptrRecords, srvTargets, aTargets, preferredTransports);

    // NAPTR present but no usable target (all records unknown-service, filtered
    // by preferredTransports, or invalid replacement across every ORDER tier):
    // fall back to direct SRV resolution, mirroring performServiceResolutionAsync.
    if (srvTargets.empty() && aTargets.empty())
    {
      return performDirectSrvResolution(domain, preferredTransports, std::nullopt);
    }

    // Step 3: Query SRV records for 'S' flag targets
    for (const auto &srvTarget : srvTargets)
    {
      try
      {
        DnsResult srvResult = query(DnsQuestion(srvTarget.srvName, DnsType::SRV, DnsClass::IN));
        processSrvRecords(srvResult.srv_records, srvTarget.service, result, srvTarget.naptrPreference);
      }
      catch (const DnsResolverException &)
      {
        // Skip failed SRV queries, continue with others
        continue;
      }
    }

    // Step 3b: Resolve 'A' flag targets directly via A/AAAA (no SRV)
    for (const auto &aTarget : aTargets)
    {
      ServiceTarget target;
      target.hostname = aTarget.hostname;
      target.port = getDefaultServicePort(aTarget.service);
      target.transport = aTarget.service;
      target.priority = 0;
      target.weight = 0;
      target.naptrPreference = aTarget.preference;
      result.targets.push_back(target);
    }

    // Step 4: Resolve hostnames to IP addresses
    resolveTargetAddresses(result);

    // Step 5: Sort targets by priority
    sortTargetsByPriority(result);

    return result;
  }

  /// \brief Perform SIP resolution asynchronously
  /// \param domain Domain to resolve
  /// \param callback Result callback
  /// \param preferredTransports Preferred transport types
  void performServiceResolutionAsync(const std::string &domain, ServiceResolutionCallback callback,
                                     const std::vector<ServiceType> &preferredTransports)
  {
    // Step 1: Start with async NAPTR query
    DnsQuestion naptrQuestion(domain, DnsType::NAPTR, DnsClass::IN);

    auto self = shared_from_this();
    transport_->queryAsync(
      naptrQuestion,
      [self, domain, callback, preferredTransports](const DnsResult &naptrResult,
                                                    const std::exception_ptr &naptrError)
      {
        if (naptrError)
        {
          // No NAPTR records, try direct SRV resolution
          self->performDirectSrvResolutionAsync(domain, callback, preferredTransports, std::nullopt);
          return;
        }

        // Process NAPTR records to get SRV and direct-A targets
        std::vector<NaptrSrvTarget> srvTargets;
        std::vector<NaptrDirectTarget> aTargets;
        try
        {
          self->processNaptrRecords(naptrResult.naptr_records, srvTargets, aTargets, preferredTransports);
        }
        catch (const std::exception &e)
        {
          callback(ServiceResolutionResult(domain), std::make_exception_ptr(e));
          return;
        }

        if (srvTargets.empty() && aTargets.empty())
        {
          // No valid targets, try direct SRV resolution
          self->performDirectSrvResolutionAsync(domain, callback, preferredTransports, std::nullopt);
          return;
        }

        // Chain SRV queries asynchronously
        auto result = std::make_shared<ServiceResolutionResult>(domain);

        // Add 'A' flag targets directly (no SRV query needed)
        for (const auto &aTarget : aTargets)
        {
          ServiceTarget target;
          target.hostname = aTarget.hostname;
          target.port = self->getDefaultServicePort(aTarget.service);
          target.transport = aTarget.service;
          target.priority = 0;
          target.weight = 0;
          target.naptrPreference = aTarget.preference;
          result->targets.push_back(target);
        }

        if (srvTargets.empty())
        {
          // Only A-flag targets — resolve addresses and return
          self->resolveTargetAddressesAsync(result, callback);
          return;
        }

        auto remainingQueries = std::make_shared<std::atomic<size_t>>(srvTargets.size());
        // callbackFired ensures the completion callback is invoked exactly once
        auto callbackFired = std::make_shared<std::atomic<bool>>(false);
        // Mutex protects concurrent writes to result->targets from parallel SRV callbacks
        auto resultMutex = std::make_shared<std::mutex>();

        for (const auto &srvTarget : srvTargets)
        {
          DnsQuestion srvQuestion(srvTarget.srvName, DnsType::SRV, DnsClass::IN);
          auto service = srvTarget.service;
          auto naptrPref = srvTarget.naptrPreference;

          self->transport_->queryAsync(
            srvQuestion,
            [self, result, service, naptrPref, remainingQueries, callbackFired, resultMutex,
             callback](const DnsResult &srvResult, const std::exception_ptr &srvError)
            {
              if (!srvError)
              {
                try
                {
                  std::lock_guard<std::mutex> lock(*resultMutex);
                  self->processSrvRecords(srvResult.srv_records, service, *result, naptrPref);
                }
                catch (...)
                {
                  // Ignore individual SRV processing errors
                }
              }

              // Check if all SRV queries are complete (acq_rel publishes each
              // callback's locked target writes to the joining thread).
              if (remainingQueries->fetch_sub(1, std::memory_order_acq_rel) == 1 &&
                  !callbackFired->exchange(true))
              {
                // All SRV queries done, now resolve hostnames asynchronously
                self->resolveTargetAddressesAsync(result, callback);
              }
            });
        }
      });
  }

  /// \brief Process cached SIP resolution from NAPTR result
  /// \param result Result to populate
  /// \param naptrResult Cached NAPTR result
  /// \param preferredTransports Preferred transport types
  void processCachedServiceResolution(ServiceResolutionResult &result, const DnsResult &naptrResult,
                                      const std::vector<ServiceType> &preferredTransports)
  {
    // Step 1: Process NAPTR records to get SRV and direct-A targets
    std::vector<NaptrSrvTarget> srvTargets;
    std::vector<NaptrDirectTarget> aTargets;
    processNaptrRecords(naptrResult.naptr_records, srvTargets, aTargets, preferredTransports);

    if (srvTargets.empty() && aTargets.empty())
    {
      // No valid NAPTR targets found
      return;
    }

    // Add 'A' flag targets directly (no SRV query needed)
    for (const auto &aTarget : aTargets)
    {
      ServiceTarget target;
      target.hostname = aTarget.hostname;
      target.port = getDefaultServicePort(aTarget.service);
      target.transport = aTarget.service;
      target.priority = 0;
      target.weight = 0;
      target.naptrPreference = aTarget.preference;
      result.targets.push_back(target);
    }

    // Step 2: Try to get SRV records from cache for each target
    for (const auto &srvTarget : srvTargets)
    {
      if (!cache_)
      {
        continue;
      }

      DnsQuestion srvQuestion(srvTarget.srvName, DnsType::SRV, DnsClass::IN);
      DnsResult srvResult;
      if (cache_->get(srvQuestion, srvResult))
      {
        processSrvRecords(srvResult.srv_records, srvTarget.service, result, srvTarget.naptrPreference);
      }
    }

    // Step 3: Try to resolve hostnames from cache
    for (auto &target : result.targets)
    {
      if (!cache_)
      {
        continue;
      }

      // Try A records first
      DnsQuestion aQuestion(target.hostname, DnsType::A, DnsClass::IN);
      DnsResult aResult;
      if (cache_->get(aQuestion, aResult))
      {
        for (const auto &record : aResult.a_records)
        {
          target.addresses.push_back(record.address);
        }
      }

      // Try AAAA records if no A records found or if we want both
      if (target.addresses.empty())
      {
        DnsQuestion aaaaQuestion(target.hostname, DnsType::AAAA, DnsClass::IN);
        DnsResult aaaaResult;
        if (cache_->get(aaaaQuestion, aaaaResult))
        {
          for (const auto &record : aaaaResult.aaaa_records)
          {
            target.addresses.push_back(record.address);
          }
        }
      }
    }

    // Step 4: Remove targets with no resolved addresses
    result.targets.erase(std::remove_if(result.targets.begin(), result.targets.end(),
                                        [](const ServiceTarget &target)
                                        { return target.addresses.empty(); }),
                         result.targets.end());

    // Step 5: Sort targets by priority
    sortTargetsByPriority(result);
  }

  /// \brief Process NAPTR records to extract SRV and direct-A targets
  /// \param naptrRecords NAPTR records to process
  /// \param srvTargets Output: 'S' flag records (replacement is SRV domain name)
  /// \param aTargets Output: 'A' flag records (replacement is hostname for direct A/AAAA)
  /// \param preferredTransports Preferred transport types
  void processNaptrRecords(const std::vector<NaptrRecord> &naptrRecords,
                           std::vector<NaptrSrvTarget> &srvTargets,
                           std::vector<NaptrDirectTarget> &aTargets,
                           const std::vector<ServiceType> &preferredTransports)
  {
    if (naptrRecords.empty())
    {
      return;
    }

    // Sort NAPTR records by order then preference
    auto sortedRecords = naptrRecords;
    std::sort(sortedRecords.begin(), sortedRecords.end(),
              [](const NaptrRecord &a, const NaptrRecord &b)
              {
                if (a.order != b.order)
                {
                  return a.order < b.order;
                }
                return a.preference < b.preference;
              });

    // RFC 3403 §4.1 (records are processed lowest ORDER first) and §8 (a NAPTR
    // processor advances to the next ORDER value only when the current one
    // yields no usable target). Records are already sorted by (order,
    // preference); walk them tier by tier and stop as soon as a completed ORDER
    // tier has produced at least one target.
    std::uint16_t currentOrder = sortedRecords.front().order;

    // Process records to extract targets
    for (const auto &record : sortedRecords)
    {
      if (record.order != currentOrder)
      {
        // Finished the current ORDER tier: if it produced any usable target,
        // stop (do not descend to higher orders); otherwise advance to this one.
        if (!srvTargets.empty() || !aTargets.empty())
        {
          break;
        }
        currentOrder = record.order;
      }

      ServiceType service = parseServiceType(record.service);
      if (service == ServiceType::Unknown)
      {
        continue;
      }

      // Check if this service type is preferred (if preferences specified)
      if (!preferredTransports.empty())
      {
        if (std::find(preferredTransports.begin(), preferredTransports.end(), service) ==
            preferredTransports.end())
        {
          continue; // Skip non-preferred transports
        }
      }

      // Skip records with empty or terminal-dot replacement
      if (record.replacement.empty() || record.replacement == ".")
      {
        continue;
      }

      // Validate replacement as a hostname (RFC 3403 §4)
      if (!validateNaptrReplacement(record.replacement))
      {
        continue;
      }

      // Case-insensitive flag check (RFC 3403, locale-independent ASCII)
      std::string flags = iora::core::StringUtils::toUpper(record.flags);

      if (flags.find('S') != std::string::npos)
      {
        // 'S' flag: replacement is an SRV domain name
        srvTargets.push_back({service, record.replacement, record.preference});
      }
      else if (flags.find('A') != std::string::npos)
      {
        // 'A' flag: replacement is a hostname for direct A/AAAA lookup (skip SRV)
        aTargets.push_back({service, record.replacement, record.order, record.preference});
      }
      // 'U' flag (terminal URI via regexp) and empty flag (chained NAPTR) are
      // intentionally not handled. RFC 3263 §4.1 defines both 'S' and 'A' flag
      // semantics for SIP. ENUM (RFC 6116) uses 'U' flag with regexp — out of scope.
      // Chained NAPTR (empty flag → query replacement as new NAPTR) is not
      // implemented; such records are skipped.
    }
  }

  /// \brief Process SRV records and add to result
  /// \param srvRecords SRV records to process
  /// \param service Service type for these records
  /// \param result Result to populate
  /// \brief Build the SRV query list (custom, or the default SIP service set) and
  /// order it by the caller's preferred transports. Shared by the sync and async
  /// direct-SRV paths so the query set and ordering are defined once.
  std::vector<std::pair<std::string, ServiceType>> buildOrderedSrvQueries(
    const std::string &domain,
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries,
    const std::vector<ServiceType> &preferredTransports) const
  {
    std::vector<std::pair<std::string, ServiceType>> actualSrvQueries;
    if (srvQueries.has_value())
    {
      actualSrvQueries = srvQueries.value();
    }
    else
    {
      actualSrvQueries = {{"_sips._tcp." + domain, ServiceType::SIPS_TLS},
                          {"_sip._tcp." + domain, ServiceType::SIP_TCP},
                          {"_sip._udp." + domain, ServiceType::SIP_UDP},
                          {"_sip._sctp." + domain, ServiceType::SIP_SCTP}};
    }

    if (!preferredTransports.empty())
    {
      std::sort(actualSrvQueries.begin(), actualSrvQueries.end(),
                [&preferredTransports](const auto &a, const auto &b)
                {
                  auto pos_a =
                    std::find(preferredTransports.begin(), preferredTransports.end(), a.second);
                  auto pos_b =
                    std::find(preferredTransports.begin(), preferredTransports.end(), b.second);

                  if (pos_a == preferredTransports.end() && pos_b == preferredTransports.end())
                  {
                    return false; // Both not preferred, keep original order
                  }
                  if (pos_a == preferredTransports.end())
                  {
                    return false; // a not preferred, b preferred
                  }
                  if (pos_b == preferredTransports.end())
                  {
                    return true; // a preferred, b not preferred
                  }

                  return pos_a < pos_b; // Both preferred, order by preference
                });
    }

    return actualSrvQueries;
  }

  /// \brief Compute the A/AAAA-fallback transport list: the preferred transports
  /// (or default UDP when none are given), minus any service an SRV "." declared
  /// unavailable (RFC 2782). An empty result means every candidate transport was
  /// denied, so no fallback target is produced.
  std::vector<ServiceType> fallbackTransports(const std::vector<ServiceType> &preferredTransports,
                                              const std::vector<ServiceType> &deniedServices) const
  {
    std::vector<ServiceType> transports = preferredTransports;
    if (transports.empty())
    {
      transports.push_back(ServiceType::SIP_UDP);
    }
    transports.erase(std::remove_if(transports.begin(), transports.end(),
                                    [&deniedServices](ServiceType t)
                                    {
                                      return std::find(deniedServices.begin(),
                                                       deniedServices.end(),
                                                       t) != deniedServices.end();
                                    }),
                     transports.end());
    return transports;
  }

  /// \brief Append one fallback ServiceTarget per transport (same domain host and
  /// resolved addresses, no SRV priority/weight). Shared by the sync and async
  /// A/AAAA-fallback paths so the target-construction loop lives in one place.
  void appendFallbackTargets(ServiceResolutionResult &result, const std::string &domain,
                             const std::vector<ServiceType> &transports,
                             const std::vector<std::string> &addresses) const
  {
    for (ServiceType transport : transports)
    {
      ServiceTarget target;
      target.hostname = domain;
      target.port = getDefaultServicePort(transport);
      target.transport = transport;
      target.priority = 0;
      target.weight = 0;
      target.addresses = addresses;

      result.targets.push_back(target);
    }
  }

  /// \brief Apply the cache-write policy for a completed query result.
  ///
  /// Positive results are cached; NXDOMAIN and NODATA (NOERROR with no answer
  /// records) are negatively cached per RFC 2308 — but ONLY when the response
  /// carries an SOA record (RFC 2308 §5: a negative response without an SOA
  /// SHOULD NOT be cached, as there is no authoritative TTL to bound it).
  void cacheQueryResult(const DnsQuestion &question, const DnsResult &result)
  {
    if (!cache_)
    {
      return;
    }

    if (result.isSuccess())
    {
      cache_->put(question, result);
      return;
    }

    // Negative response: only cache it if it carries an SOA (RFC 2308 §5).
    if (!negativeResponseHasSoa(result))
    {
      return;
    }

    if (result.header.rcode == DnsResponseCode::NXDOMAIN)
    {
      cache_->putNegative(question, result, "Domain not found (NXDOMAIN)");
    }
    else if (result.header.rcode == DnsResponseCode::NOERROR)
    {
      // NODATA (NOERROR with no answer records) — RFC 2308 §2.2. Caching this
      // stops the common "name exists but no records of this type" case (e.g. a
      // domain publishing SRV but no NAPTR) from re-querying on every lookup.
      cache_->putNegative(question, result, "No records of requested type (NODATA)");
    }
  }

  /// \brief True if a negative response carries an SOA (in the parsed SOA set or
  /// the authority section) — the prerequisite for RFC 2308 negative caching.
  static bool negativeResponseHasSoa(const DnsResult &result)
  {
    if (!result.soa_records.empty())
    {
      return true;
    }
    for (const auto &rr : result.authority)
    {
      if (rr.type == DnsType::SOA)
      {
        return true;
      }
    }
    return false;
  }

  /// \param naptrPref NAPTR preference for this SRV group (0 if not from NAPTR)
  /// \return true if any SRV record carried the RFC 2782 "." target — meaning the
  ///         service is decidedly NOT available at this domain; such records are
  ///         skipped and the caller should suppress any A/AAAA fallback.
  bool processSrvRecords(const std::vector<SrvRecord> &srvRecords, ServiceType service,
                         ServiceResolutionResult &result, std::uint16_t naptrPref = 0)
  {
    bool serviceUnavailable = false;
    for (const auto &record : srvRecords)
    {
      // RFC 2782: a Target of "." means the service is decidedly not available at
      // this domain. The parser represents a present root target as "." (distinct
      // from a malformed record with no target field). Skip it and flag the caller
      // so it suppresses the A/AAAA fallback for THIS service.
      if (record.target == ".")
      {
        serviceUnavailable = true;
        continue;
      }

      // A malformed SRV whose target field is absent decodes to an empty string.
      // It is not a connectable target, but it is not a deliberate "." abort
      // either: skip it WITHOUT signalling service-unavailable.
      if (record.target.empty())
      {
        continue;
      }

      ServiceTarget target;
      target.hostname = record.target;
      target.port = record.port;
      target.transport = service;
      target.priority = record.priority;
      target.weight = record.weight;
      target.naptrPreference = naptrPref;

      result.targets.push_back(target);
    }
    return serviceUnavailable;
  }

  /// \brief Resolve IP addresses for all targets
  /// \param result Result containing targets to resolve
  void resolveTargetAddresses(ServiceResolutionResult &result)
  {
    for (auto &target : result.targets)
    {
      try
      {
        target.addresses = resolveHostname(target.hostname, false);
      }
      catch (const DnsResolverException &)
      {
        // Skip targets that can't be resolved
        target.addresses.clear();
      }
    }

    // Remove targets with no resolved addresses
    result.targets.erase(std::remove_if(result.targets.begin(), result.targets.end(),
                                        [](const ServiceTarget &target)
                                        { return target.addresses.empty(); }),
                         result.targets.end());
  }

  /// \brief Sort targets by NAPTR preference then SRV priority
  /// NAPTR preference (RFC 3403 §4.1) is the primary key — lower = preferred transport.
  /// SRV priority (RFC 2782) is the secondary key — lower = higher precedence within
  /// the same NAPTR preference tier.
  void sortTargetsByPriority(ServiceResolutionResult &result)
  {
    std::stable_sort(result.targets.begin(), result.targets.end(),
                     [](const ServiceTarget &a, const ServiceTarget &b)
                     {
                       if (a.naptrPreference != b.naptrPreference)
                       {
                         return a.naptrPreference < b.naptrPreference;
                       }
                       return a.priority < b.priority;
                     });
  }

  /// \brief Fallback to A/AAAA resolution when no SRV records exist
  /// \param domain Domain to resolve
  /// \param result Result to populate
  /// \param preferredTransports Preferred transport types
  void performFallbackResolution(const std::string &domain, ServiceResolutionResult &result,
                                 const std::vector<ServiceType> &preferredTransports,
                                 const std::vector<ServiceType> &deniedServices = {})
  {
    try
    {
      // Transports to build fallback targets for, minus any SRV-"." denied service.
      std::vector<ServiceType> transports = fallbackTransports(preferredTransports, deniedServices);
      if (transports.empty())
      {
        return; // Every candidate transport was declared unavailable (RFC 2782).
      }

      auto addresses = resolveHostname(domain, false);

      appendFallbackTargets(result, domain, transports, addresses);
    }
    catch (const DnsResolverException &)
    {
      // No fallback possible
    }
  }

  /// \brief Perform fallback resolution asynchronously
  /// \param domain Domain to resolve
  /// \param result Shared result to populate
  /// \param callback Result callback
  /// \param preferredTransports Preferred transport types
  void performFallbackResolutionAsync(const std::string &domain,
                                      std::shared_ptr<ServiceResolutionResult> result,
                                      ServiceResolutionCallback callback,
                                      const std::vector<ServiceType> &preferredTransports,
                                      const std::vector<ServiceType> &deniedServices = {})
  {
    // Transports to build fallback targets for, minus any SRV-"." denied service.
    // If none remain, there is nothing to resolve — fire the callback immediately.
    auto transportsToUse = fallbackTransports(preferredTransports, deniedServices);
    if (transportsToUse.empty())
    {
      callback(*result, nullptr);
      return;
    }

    DnsQuestion aQuestion(domain, DnsType::A, DnsClass::IN);

    auto self = shared_from_this();
    transport_->queryAsync(
      aQuestion,
      [self, domain, result, callback, transportsToUse](const DnsResult &aResult,
                                                        const std::exception_ptr &aError)
      {
        std::vector<std::string> addresses;

        if (!aError)
        {
          for (const auto &record : aResult.a_records)
          {
            addresses.push_back(record.address);
          }
        }

        if (addresses.empty())
        {
          // Try AAAA if A failed
          DnsQuestion aaaaQuestion(domain, DnsType::AAAA, DnsClass::IN);

          self->transport_->queryAsync(aaaaQuestion,
                                 [self, result, callback, domain, transportsToUse, addresses](
                                   const DnsResult &aaaaResult, const std::exception_ptr &aaaaError)
                                 {
                                   std::vector<std::string> finalAddresses = addresses;

                                   if (!aaaaError)
                                   {
                                     for (const auto &record : aaaaResult.aaaa_records)
                                     {
                                       finalAddresses.push_back(record.address);
                                     }
                                   }

                                   // Create fallback targets
                                   self->appendFallbackTargets(*result, domain, transportsToUse,
                                                               finalAddresses);

                                   callback(*result, nullptr);
                                 });
        }
        else
        {
          // Create fallback targets with A records
          self->appendFallbackTargets(*result, domain, transportsToUse, addresses);

          callback(*result, nullptr);
        }
      });
  }

  /// \brief Resolve target addresses asynchronously
  /// \param result Result containing targets to resolve (must be shared_ptr for async safety)
  /// \param callback Result callback
  void resolveTargetAddressesAsync(std::shared_ptr<ServiceResolutionResult> result,
                                   ServiceResolutionCallback callback)
  {
    if (result->targets.empty())
    {
      callback(*result, nullptr);
      return;
    }

    // Store initial target count to avoid race conditions during async operations
    const std::size_t initialTargetCount = result->targets.size();
    auto remainingTargets = std::make_shared<std::atomic<size_t>>(initialTargetCount);

    // Keep the resolver alive across the async A/AAAA callbacks: the caller's
    // strong reference is released when its own callback returns, so the callbacks
    // this method queues must own a strong ref (fire-and-forget resolution).
    auto self = shared_from_this();

    // Process targets by index with bounds safety
    for (size_t targetIndex = 0; targetIndex < initialTargetCount; ++targetIndex)
    {
      std::string hostname = result->targets[targetIndex].hostname;
      DnsQuestion aQuestion(hostname, DnsType::A, DnsClass::IN);

      transport_->queryAsync(
        aQuestion,
        [self, targetIndex, initialTargetCount, remainingTargets, result, callback,
         hostname](const DnsResult &aResult, const std::exception_ptr &aError)
        {
          // Safe bounds check using initial count (targets vector won't be modified until all
          // complete)
          if (!aError && targetIndex < initialTargetCount)
          {
            for (const auto &record : aResult.a_records)
            {
              result->targets[targetIndex].addresses.push_back(record.address);
            }
          }

          // Try AAAA if no A records found
          if (targetIndex < initialTargetCount && result->targets[targetIndex].addresses.empty())
          {
            DnsQuestion aaaaQuestion(hostname, DnsType::AAAA, DnsClass::IN);

            self->transport_->queryAsync(
              aaaaQuestion,
              [self, targetIndex, initialTargetCount, remainingTargets, result,
               callback](const DnsResult &aaaaResult, const std::exception_ptr &aaaaError)
              {
                if (!aaaaError && targetIndex < initialTargetCount)
                {
                  for (const auto &record : aaaaResult.aaaa_records)
                  {
                    result->targets[targetIndex].addresses.push_back(record.address);
                  }
                }

                // Check if all targets are resolved (acq_rel publishes each
                // target's writes to the joining thread; see the SRV completer).
                if (remainingTargets->fetch_sub(1, std::memory_order_acq_rel) == 1)
                {
                  // Remove targets with no addresses and sort
                  result->targets.erase(
                    std::remove_if(result->targets.begin(), result->targets.end(),
                                   [](const ServiceTarget &t) { return t.addresses.empty(); }),
                    result->targets.end());

                  self->sortTargetsByPriority(*result);

                  callback(*result, nullptr);
                }
              });
          }
          else
          {
            // Check if all targets are resolved
            if (remainingTargets->fetch_sub(1, std::memory_order_acq_rel) == 1)
            {
              // Remove targets with no addresses and sort
              result->targets.erase(std::remove_if(result->targets.begin(), result->targets.end(),
                                                   [](const ServiceTarget &t)
                                                   { return t.addresses.empty(); }),
                                    result->targets.end());

              self->sortTargetsByPriority(*result);

              callback(*result, nullptr);
            }
          }
        });
    }
  }
};

// =============================================================================
// Backward Compatibility Aliases (SIP-specific names)
// =============================================================================

/// \brief Backward compatibility alias for SIP applications
/// \deprecated Use ServiceType instead for broader applicability
using SipServiceType = ServiceType;

/// \brief Backward compatibility alias for SIP applications
/// \deprecated Use ServiceTarget instead for broader applicability
using SipTarget = ServiceTarget;

/// \brief Backward compatibility alias for SIP applications
/// \deprecated Use ServiceResolutionResult instead for broader applicability
using SipResolutionResult = ServiceResolutionResult;

} // namespace dns
} // namespace network
} // namespace iora