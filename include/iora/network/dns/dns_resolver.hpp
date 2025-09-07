// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include "dns_cache.hpp"
#include "dns_transport.hpp"
#include "dns_types.hpp"
#include <algorithm>
#include <cctype>
#include <functional>
#include <memory>
#include <random>
#include <regex>
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
  SIP_TCP,   ///< SIP over TCP
  SIP_UDP,   ///< SIP over UDP
  SIP_SCTP,  ///< SIP over SCTP
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
           transport == ServiceType::HTTPS_TCP;
  }
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

    // Find all targets with highest priority (lowest numeric value)
    std::uint16_t best_priority = targets[0].priority;
    std::vector<ServiceTarget> candidates;

    for (const auto &target : targets)
    {
      if (target.priority < best_priority)
      {
        best_priority = target.priority;
        candidates.clear();
        candidates.push_back(target);
      }
      else if (target.priority == best_priority)
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

    // Find all targets with highest priority (lowest numeric value)
    std::uint16_t best_priority = targets[0].priority;
    std::vector<ServiceTarget> candidates;

    for (const auto &target : targets)
    {
      if (target.priority < best_priority)
      {
        best_priority = target.priority;
        candidates.clear();
        candidates.push_back(target);
      }
      else if (target.priority == best_priority)
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
  void setRngSeed(std::uint32_t seed) { rng_.seed(seed); }

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

    // Cache results (positive and negative)
    if (cache_)
    {
      if (result.isSuccess())
      {
        cache_->put(question, result);
      }
      else if (result.header.rcode == DnsResponseCode::NXDOMAIN)
      {
        // Negative caching for NXDOMAIN responses per RFC 2308
        cache_->putNegative(question, result, "Domain not found (NXDOMAIN)");
      }
    }

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

        // Cache results (positive and negative)
        if (self->cache_)
        {
          if (result.isSuccess())
          {
            self->cache_->put(question, result);
          }
          else if (result.header.rcode == DnsResponseCode::NXDOMAIN)
          {
            // Negative caching for NXDOMAIN responses per RFC 2308
            self->cache_->putNegative(question, result, "Domain not found (NXDOMAIN)");
          }
        }

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

    // Use provided SRV queries or default to common SIP services for backward compatibility
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

    // Reorder based on preferences
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

    // Query SRV records
    for (const auto &[srvName, service] : actualSrvQueries)
    {
      try
      {
        DnsResult srvResult = query(DnsQuestion(srvName, DnsType::SRV, DnsClass::IN));
        processSrvRecords(srvResult.srv_records, service, result);
      }
      catch (const DnsResolverException &)
      {
        // Skip failed queries
        continue;
      }
    }

    // If no SRV records found, fall back to A/AAAA records
    if (result.targets.empty())
    {
      performFallbackResolution(domain, result, preferredTransports);
    }
    else
    {
      resolveTargetAddresses(result);
      sortTargetsByPriority(result);
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
    // Use provided SRV queries or default to common SIP services for backward compatibility
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

    // Reorder based on preferences
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

    // Chain SRV queries asynchronously
    auto result = std::make_shared<ServiceResolutionResult>(domain);
    auto remainingQueries = std::make_shared<std::atomic<size_t>>(actualSrvQueries.size());
    // firstCompleter ensures only the first thread to complete calls the callback
    auto firstCompleter = std::make_shared<std::atomic<bool>>(false);

    for (const auto &[srvName, service] : actualSrvQueries)
    {
      DnsQuestion srvQuestion(srvName, DnsType::SRV, DnsClass::IN);

      auto self = shared_from_this();
      transport_->queryAsync(
        srvQuestion,
        [self, result, service, remainingQueries, firstCompleter, callback, domain,
         preferredTransports](const DnsResult &srvResult, const std::exception_ptr &srvError)
        {
          if (!srvError && !firstCompleter->load())
          {
            try
            {
              self->processSrvRecords(srvResult.srv_records, service, *result);
            }
            catch (...)
            {
              // Ignore individual SRV processing errors
            }
          }

          // Check if all SRV queries are complete
          if (--(*remainingQueries) == 0 && !firstCompleter->exchange(true))
          {
            // If no SRV records found, fall back to A/AAAA
            if (result->targets.empty())
            {
              self->performFallbackResolutionAsync(domain, result, callback, preferredTransports);
            }
            else
            {
              self->resolveTargetAddressesAsync(result, callback);
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
  mutable std::mt19937 rng_; ///< Thread-local not needed since resolver is stateful

  // =============================================================================
  // Input Validation Functions (RFC Compliance & Security)
  // =============================================================================

  /// \brief Validate hostname according to RFC 1035
  /// \param hostname Hostname to validate
  /// \return true if valid, false otherwise
  bool validateHostname(const std::string &hostname) const
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
          if (!std::isalnum(c) && c != '-')
          {
            return false; // Only alphanumeric and hyphen allowed
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

    // Check for valid SIP service patterns
    if (service == "SIPS+D2T" || service == "SIPS+D2S" || service == "SIP+D2T" ||
        service == "SIP+D2U" || service == "SIP+D2S")
    {
      return true; // Known good SIP services
    }

    // Basic format validation: should be alphanumeric with +, -, _
    for (char c : service)
    {
      if (!std::isalnum(c) && c != '+' && c != '-' && c != '_')
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

    return validateHostname(replacement);
  }

  /// \brief Validate NAPTR regex field (basic safety check)
  /// \param regex NAPTR regex pattern
  /// \return true if appears safe, false otherwise
  bool validateNaptrRegex(const std::string &regex) const
  {
    if (regex.empty() || regex.length() > 255)
    {
      return false; // Reasonable length limit
    }

    // Check for potentially dangerous regex constructs
    if (regex.find("(.*)(.*)") != std::string::npos)
    {
      return false; // Potential ReDoS pattern
    }

    if (std::count(regex.begin(), regex.end(), '(') > 10)
    {
      return false; // Too many capture groups
    }

    // Basic regex syntax validation
    try
    {
      std::regex testRegex(regex);
      return true;
    }
    catch (const std::exception &)
    {
      return false; // Invalid regex syntax
    }
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
      else if (std::isspace(c))
      {
        sanitized.push_back(' ');
      }
      // Skip other characters
    }

    return sanitized;
  }

  /// \brief Parse service type from NAPTR service field
  /// \param service NAPTR service string (e.g., "SIP+D2U", "SIPS+D2T", "HTTP+D2T")
  /// \return Parsed service type
  ServiceType parseServiceType(const std::string &service) const
  {
    // Validate service string first
    if (!validateNaptrService(service))
    {
      return ServiceType::Unknown;
    }

    // SIP service mappings
    if (service == "SIPS+D2T")
      return ServiceType::SIPS_TLS;
    if (service == "SIPS+D2S")
      return ServiceType::SIPS_SCTP;
    if (service == "SIP+D2T")
      return ServiceType::SIP_TCP;
    if (service == "SIP+D2U")
      return ServiceType::SIP_UDP;
    if (service == "SIP+D2S")
      return ServiceType::SIP_SCTP;

    // HTTP service mappings
    if (service == "HTTP+D2T")
      return ServiceType::HTTP_TCP;
    if (service == "HTTPS+D2T")
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
    case ServiceType::SIP_TCP:
      return 5060;
    case ServiceType::SIP_UDP:
      return 5060;
    case ServiceType::SIP_SCTP:
      return 5060;
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

    // Step 2: Process NAPTR records to get SRV targets
    std::vector<std::pair<ServiceType, std::string>> srvTargets;
    processNaptrRecords(naptrRecords, srvTargets, preferredTransports);

    // Step 3: Query SRV records for each target
    for (const auto &[service, srvName] : srvTargets)
    {
      try
      {
        DnsResult srvResult = query(DnsQuestion(srvName, DnsType::SRV, DnsClass::IN));
        processSrvRecords(srvResult.srv_records, service, result);
      }
      catch (const DnsResolverException &)
      {
        // Skip failed SRV queries, continue with others
        continue;
      }
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

        // Process NAPTR records to get SRV targets
        std::vector<std::pair<ServiceType, std::string>> srvTargets;
        try
        {
          self->processNaptrRecords(naptrResult.naptr_records, srvTargets, preferredTransports);
        }
        catch (const std::exception &e)
        {
          callback(ServiceResolutionResult(domain), std::make_exception_ptr(e));
          return;
        }

        if (srvTargets.empty())
        {
          // No valid SRV targets, try direct SRV resolution
          self->performDirectSrvResolutionAsync(domain, callback, preferredTransports, std::nullopt);
          return;
        }

        // Chain SRV queries asynchronously
        auto result = std::make_shared<ServiceResolutionResult>(domain);
        auto remainingQueries = std::make_shared<std::atomic<size_t>>(srvTargets.size());
        // firstCompleter ensures only the first thread to complete calls the callback
        auto firstCompleter = std::make_shared<std::atomic<bool>>(false);

        for (const auto &[service, srvName] : srvTargets)
        {
          DnsQuestion srvQuestion(srvName, DnsType::SRV, DnsClass::IN);

          self->transport_->queryAsync(
            srvQuestion,
            [self, result, service, remainingQueries, firstCompleter,
             callback](const DnsResult &srvResult, const std::exception_ptr &srvError)
            {
              if (!srvError && !firstCompleter->load())
              {
                try
                {
                  self->processSrvRecords(srvResult.srv_records, service, *result);
                }
                catch (...)
                {
                  // Ignore individual SRV processing errors
                }
              }

              // Check if all SRV queries are complete
              if (--(*remainingQueries) == 0 && !firstCompleter->exchange(true))
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
    // Step 1: Process NAPTR records to get SRV targets
    std::vector<std::pair<ServiceType, std::string>> srvTargets;
    processNaptrRecords(naptrResult.naptr_records, srvTargets, preferredTransports);

    if (srvTargets.empty())
    {
      // No valid NAPTR targets found
      return;
    }

    // Step 2: Try to get SRV records from cache for each target
    for (const auto &[service, srvName] : srvTargets)
    {
      if (!cache_)
      {
        continue;
      }

      DnsQuestion srvQuestion(srvName, DnsType::SRV, DnsClass::IN);
      DnsResult srvResult;
      if (cache_->get(srvQuestion, srvResult))
      {
        // Process SRV records and add to result
        processSrvRecords(srvResult.srv_records, service, result);
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

  /// \brief Process NAPTR records to extract SRV targets
  /// \param naptrRecords NAPTR records to process
  /// \param srvTargets Output vector of SRV targets
  /// \param preferredTransports Preferred transport types
  void processNaptrRecords(const std::vector<NaptrRecord> &naptrRecords,
                           std::vector<std::pair<ServiceType, std::string>> &srvTargets,
                           const std::vector<ServiceType> &preferredTransports)
  {
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

    // Process records to extract SRV targets
    for (const auto &record : sortedRecords)
    {
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

      // Extract SRV target from replacement field
      if (!record.replacement.empty() && record.flags.find('S') != std::string::npos)
      {
        srvTargets.emplace_back(service, record.replacement);
      }
    }
  }

  /// \brief Process SRV records and add to result
  /// \param srvRecords SRV records to process
  /// \param service Service type for these records
  /// \param result Result to populate
  void processSrvRecords(const std::vector<SrvRecord> &srvRecords, ServiceType service,
                         ServiceResolutionResult &result)
  {
    for (const auto &record : srvRecords)
    {
      ServiceTarget target;
      target.hostname = record.target;
      target.port = record.port;
      target.transport = service;
      target.priority = record.priority;
      target.weight = record.weight;

      result.targets.push_back(target);
    }
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

  /// \brief Sort targets by priority (lower priority value = higher precedence)
  /// \param result Result to sort
  void sortTargetsByPriority(ServiceResolutionResult &result)
  {
    std::sort(result.targets.begin(), result.targets.end(),
              [](const ServiceTarget &a, const ServiceTarget &b)
              { return a.priority < b.priority; });
  }

  /// \brief Fallback to A/AAAA resolution when no SRV records exist
  /// \param domain Domain to resolve
  /// \param result Result to populate
  /// \param preferredTransports Preferred transport types
  void performFallbackResolution(const std::string &domain, ServiceResolutionResult &result,
                                 const std::vector<ServiceType> &preferredTransports)
  {
    try
    {
      auto addresses = resolveHostname(domain, false);

      // Create targets for preferred transports (or default UDP if none specified)
      std::vector<ServiceType> transports = preferredTransports;
      if (transports.empty())
      {
        transports.push_back(ServiceType::SIP_UDP);
      }

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
                                      const std::vector<ServiceType> &preferredTransports)
  {
    DnsQuestion aQuestion(domain, DnsType::A, DnsClass::IN);

    auto self = shared_from_this();
    transport_->queryAsync(
      aQuestion,
      [self, domain, result, callback, preferredTransports](const DnsResult &aResult,
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
                                 [self, result, callback, domain, preferredTransports, addresses](
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
                                   std::vector<ServiceType> transports = preferredTransports;
                                   if (transports.empty())
                                   {
                                     transports.push_back(ServiceType::SIP_UDP);
                                   }

                                   for (ServiceType transport : transports)
                                   {
                                     ServiceTarget target;
                                     target.hostname = domain;
                                     target.port = self->getDefaultServicePort(transport);
                                     target.transport = transport;
                                     target.priority = 0;
                                     target.weight = 0;
                                     target.addresses = finalAddresses;

                                     result->targets.push_back(target);
                                   }

                                   callback(*result, nullptr);
                                 });
        }
        else
        {
          // Create fallback targets with A records
          std::vector<ServiceType> transports = preferredTransports;
          if (transports.empty())
          {
            transports.push_back(ServiceType::SIP_UDP);
          }

          for (ServiceType transport : transports)
          {
            ServiceTarget target;
            target.hostname = domain;
            target.port = self->getDefaultServicePort(transport);
            target.transport = transport;
            target.priority = 0;
            target.weight = 0;
            target.addresses = addresses;

            result->targets.push_back(target);
          }

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

    // Process targets by index with bounds safety
    for (size_t targetIndex = 0; targetIndex < initialTargetCount; ++targetIndex)
    {
      std::string hostname = result->targets[targetIndex].hostname;
      DnsQuestion aQuestion(hostname, DnsType::A, DnsClass::IN);

      transport_->queryAsync(
        aQuestion,
        [this, targetIndex, initialTargetCount, remainingTargets, result, callback,
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

            transport_->queryAsync(
              aaaaQuestion,
              [targetIndex, initialTargetCount, remainingTargets, result,
               callback](const DnsResult &aaaaResult, const std::exception_ptr &aaaaError)
              {
                if (!aaaaError && targetIndex < initialTargetCount)
                {
                  for (const auto &record : aaaaResult.aaaa_records)
                  {
                    result->targets[targetIndex].addresses.push_back(record.address);
                  }
                }

                // Check if all targets are resolved
                if (--(*remainingTargets) == 0)
                {
                  // Remove targets with no addresses and sort
                  result->targets.erase(
                    std::remove_if(result->targets.begin(), result->targets.end(),
                                   [](const ServiceTarget &t) { return t.addresses.empty(); }),
                    result->targets.end());

                  std::sort(result->targets.begin(), result->targets.end(),
                            [](const ServiceTarget &a, const ServiceTarget &b)
                            { return a.priority < b.priority; });

                  callback(*result, nullptr);
                }
              });
          }
          else
          {
            // Check if all targets are resolved
            if (--(*remainingTargets) == 0)
            {
              // Remove targets with no addresses and sort
              result->targets.erase(std::remove_if(result->targets.begin(), result->targets.end(),
                                                   [](const ServiceTarget &t)
                                                   { return t.addresses.empty(); }),
                                    result->targets.end());

              std::sort(result->targets.begin(), result->targets.end(),
                        [](const ServiceTarget &a, const ServiceTarget &b)
                        { return a.priority < b.priority; });

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