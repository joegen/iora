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
  std::uint16_t naptrPreference{0};   ///< Transport-sequence tier — lower = preferred. On the
                                      ///< NAPTR path it is the NAPTR preference (RFC 3403 §4.1);
                                      ///< on the direct-SRV path it is the per-set transport rank
                                      ///< (buildOrderedSrvQueries index). The two are mutually
                                      ///< exclusive on one result. 0 = first tier / A fallback.
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

  /// \brief Get the preferred (head) target of the RFC-2782-ordered failover list.
  ///
  /// The failover list is ordered at construction by DnsResolver::sortTargetsByPriority,
  /// which sequences targets per SRV owner name (naptrPreference/transport-rank, transport,
  /// priority) and applies the RFC 2782 weighted-random ordering to each equal-priority group
  /// (2026-09-25-4). The preferred target is therefore simply the head of the list — selection
  /// no longer re-randomizes here (that would double-order the already-weighted list).
  ///
  /// PRECONDITION: the result was produced by DnsResolver. A hand-built, unordered
  /// ServiceResolutionResult returns its first element as-is (an unweighted pick).
  ///
  /// \return The head target, or a default-constructed ServiceTarget if the list is empty.
  ServiceTarget getPreferredTarget() const
  {
    return targets.empty() ? ServiceTarget{} : targets.front();
  }

  /// \brief API-compatibility overload. The list is already weighted-ordered at construction,
  ///        so this returns the head (same as getPreferredTarget()).
  ServiceTarget getPreferredTargetWithDefaultRng() const { return getPreferredTarget(); }

  /// \brief API-compatibility overload. The RNG is unused: the failover list is already
  ///        RFC-2782 weighted-ordered at construction, so selection returns the head and does
  ///        not re-randomize (no double-ordering).
  /// \return The head target, or a default-constructed ServiceTarget if the list is empty.
  template <typename RNG> ServiceTarget getPreferredTarget(RNG & /*rng*/) const
  {
    return targets.empty() ? ServiceTarget{} : targets.front();
  }
};

/// \brief DNS resolver exception hierarchy
class DnsResolverException : public std::exception
{
public:
  explicit DnsResolverException(const std::string &message,
                                DnsResponseCode code = DnsResponseCode::SERVFAIL)
      : _message(message), _responseCode(code)
  {
  }

  const char *what() const noexcept override { return _message.c_str(); }

  DnsResponseCode getResponseCode() const noexcept { return _responseCode; }

private:
  std::string _message;
  DnsResponseCode _responseCode;
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
      : _transport(transport), _cache(cache), _config(config)
  {
    // Initialize RNG with random seed for production use
    std::random_device rd;
    _rng.seed(rd());
  }

  /// \brief Set RNG seed for deterministic testing
  /// \param seed Seed value for reproducible randomness
  void setRngSeed(std::uint32_t seed)
  {
    std::lock_guard<std::mutex> lock(_rngMutex);
    _rng.seed(seed);
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
    if (_cache)
    {
      DnsQuestion naptrQuestion(domain, DnsType::NAPTR, DnsClass::IN);
      DnsResult naptrResult;
      if (_cache->get(naptrQuestion, naptrResult))
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
    if (_cache)
    {
      DnsQuestion naptrQuestion(domain, DnsType::NAPTR, DnsClass::IN);
      DnsResult naptrResult;
      if (_cache->get(naptrQuestion, naptrResult))
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
    if (_cache)
    {
      DnsResult result;
      if (_cache->get(question, result))
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
    DnsResult result = _transport->query(question);

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
    if (_cache)
    {
      DnsResult result;
      if (_cache->get(question, result))
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
    _transport->queryAsync(
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
    AddressResolutionPolicy policy = _config.addressResolutionPolicy;
    if (prefer_ipv6 && policy == AddressResolutionPolicy::IPv4First)
    {
      policy = AddressResolutionPolicy::IPv6First;
    }

    std::vector<std::string> ipv4Addresses;
    std::vector<std::string> ipv6Addresses;

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
        // IPv4 query failed (bad rcode / no records), continue to AAAA.
      }
      catch (const DnsTransportException &)
      {
        // IPv4 query timed out or transport error, continue to AAAA so any
        // AAAA result is still returned (RFC 3263 dual-stack partial results).
      }
      catch (const DnsParseException &)
      {
        // Defensive / currently unreachable: the transport drops-and-waits on a
        // malformed datagram (dns_transport.hpp:1804-1823), so a parse failure
        // surfaces to the resolver as a timeout, not a DnsParseException. This
        // clause is kept per the enumerate-the-three-types decision. Continue to
        // AAAA (keep partial results) if it ever does fire.
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
        // IPv6 query failed (bad rcode / no records), continue.
      }
      catch (const DnsTransportException &)
      {
        // IPv6 query timed out or transport error: DO NOT discard the A
        // results already collected above. This is the dual-stack SIP target
        // case (finding #1) — combine returns the IPv4 addresses instead of
        // throwing out of resolveHostname.
      }
      catch (const DnsParseException &)
      {
        // Defensive / currently unreachable (see the IPv4 note above): keep the
        // A results already collected and continue.
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

    // No addresses from either family -> RFC 3263 §4.2 no-record result.
    // (A former outer try/catch here re-threw an identically-constructed
    // DnsNoRecordsException; removed as a provable no-op now that the inner
    // A/AAAA catches absorb transport/parse errors — slice a1 review L-h.)
    if (addresses.empty())
    {
      throw DnsNoRecordsException(
        hostname, policy == AddressResolutionPolicy::IPv6Only ? DnsType::AAAA : DnsType::A);
    }

    return addresses;
  }

  /// \brief Get the preferred (head) target of an RFC-2782-ordered resolution result.
  ///
  /// The weighted-random ordering is applied once, at resolution time, inside
  /// sortTargetsByPriority (which draws from the resolver's _rng under _rngMutex). The
  /// preferred target is therefore just the head of the already-ordered list; this method
  /// no longer touches _rng (2026-09-25-4 fix D / TS-5 — the former _rngMutex acquisition
  /// here is dead once selection returns front()).
  ///
  /// \param result Service resolution result containing the ordered targets
  /// \return The head target of the ordered failover list
  ServiceTarget getPreferredTarget(const ServiceResolutionResult &result) const
  {
    return result.getPreferredTarget();
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
    // The query's index in the preference-ordered actualSrvQueries is the per-set transport
    // rank, stamped as naptrPreference so sortTargetsByPriority sequences transports per set
    // and never cross-compares SRV priority across owner names (2026-09-25-4 fix A).
    for (std::size_t rank = 0; rank < actualSrvQueries.size(); ++rank)
    {
      const auto &srvName = actualSrvQueries[rank].first;
      const auto service = actualSrvQueries[rank].second;
      try
      {
        DnsResult srvResult = query(DnsQuestion(srvName, DnsType::SRV, DnsClass::IN));
        if (processSrvRecords(srvResult.srv_records, service, result,
                              static_cast<std::uint16_t>(rank)))
        {
          deniedServices.push_back(service);
        }
      }
      catch (const DnsResolverException &)
      {
        // Skip failed queries
        continue;
      }
      catch (const DnsTransportException &)
      {
        // A timeout/transport error on ONE SRV set must not abort the others
        // (RFC 3263 §4.3 per-record isolation): skip and keep the rest.
        continue;
      }
      catch (const DnsParseException &)
      {
        // Defensive / currently unreachable (transport drop-and-waits on malformed
        // datagrams, dns_transport.hpp:1804-1823): skip this SRV set, keep the others.
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

    // The query's index in the preference-ordered actualSrvQueries is the per-set transport
    // rank; snapshot it per-iteration and capture BY VALUE so each completion lambda stamps its
    // own set's rank (2026-09-25-4 fix A — mirrors the NAPTR-async by-value idiom).
    for (std::size_t rank = 0; rank < actualSrvQueries.size(); ++rank)
    {
      const auto &srvName = actualSrvQueries[rank].first;
      const auto service = actualSrvQueries[rank].second;
      const auto transportRank = static_cast<std::uint16_t>(rank);
      DnsQuestion srvQuestion(srvName, DnsType::SRV, DnsClass::IN);

      auto self = shared_from_this();
      _transport->queryAsync(
        srvQuestion,
        [self, result, service, transportRank, remainingQueries, callbackFired, resultMutex,
         deniedServices, callback, domain, preferredTransports](const DnsResult &srvResult,
                                                                const std::exception_ptr &srvError)
        {
          if (!srvError)
          {
            try
            {
              std::lock_guard<std::mutex> lock(*resultMutex);
              if (self->processSrvRecords(srvResult.srv_records, service, *result, transportRank))
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
  std::shared_ptr<DnsTransport> _transport; ///< DNS transport layer
  std::shared_ptr<DnsCache> _cache;         ///< DNS cache (optional)
  DnsConfig _config;                        ///< DNS configuration

  /// \brief Centralized random number generator for deterministic testing
  mutable std::mt19937 _rng;    ///< Weighted SRV selection RNG (guarded by _rngMutex)
  mutable std::mutex _rngMutex; ///< Guards _rng against concurrent advance/seed

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

    // Every NAPTR-failure and no-usable-NAPTR path converges on the same RFC 3263
    // §4.1 direct-SRV fallback, so name it once (review L-f).
    auto fallbackToDirectSrv = [&]()
    { return performDirectSrvResolution(domain, preferredTransports, std::nullopt); };

    // Step 1: Query NAPTR records
    std::vector<NaptrRecord> naptrRecords;
    try
    {
      DnsResult naptrResult = query(DnsQuestion(domain, DnsType::NAPTR, DnsClass::IN));
      naptrRecords = naptrResult.naptr_records;
    }
    catch (const DnsResolverException &)
    {
      // No NAPTR records / bad rcode: try direct SRV queries (RFC 3263 §4.1).
      return fallbackToDirectSrv();
    }
    catch (const DnsTransportException &)
    {
      // NAPTR query timed out or transport error: fall back to direct SRV
      // (RFC 3263 §4.1) instead of aborting the whole resolution.
      return fallbackToDirectSrv();
    }
    catch (const DnsParseException &)
    {
      // Defensive / currently unreachable (transport drop-and-waits on malformed
      // datagrams -> timeout, dns_transport.hpp:1804-1823): fall back to direct SRV.
      return fallbackToDirectSrv();
    }

    // Step 2: Process NAPTR records to get SRV and direct-A targets.
    // NOTE (review L-e, declined for this slice): processNaptrRecords is
    // deliberately NOT wrapped in a try here — it throws only std::bad_alloc-class
    // errors, which SHOULD propagate ("let real bugs propagate"). The async path's
    // broader catch(std::exception) around the same call is a separate,
    // out-of-scope concern (flagged for a later review).
    std::vector<NaptrSrvTarget> srvTargets;
    std::vector<NaptrDirectTarget> aTargets;
    processNaptrRecords(naptrRecords, srvTargets, aTargets, preferredTransports);

    // NAPTR present but no usable target (all records unknown-service, filtered
    // by preferredTransports, or invalid replacement across every ORDER tier):
    // fall back to direct SRV resolution, mirroring performServiceResolutionAsync.
    if (srvTargets.empty() && aTargets.empty())
    {
      return fallbackToDirectSrv();
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
      catch (const DnsTransportException &)
      {
        // A timeout/transport error on one NAPTR-derived SRV target must not
        // abort the sibling targets (RFC 3263 §4.3): skip and continue.
        continue;
      }
      catch (const DnsParseException &)
      {
        // Defensive / currently unreachable (transport drop-and-waits on malformed
        // datagrams, dns_transport.hpp:1804-1823): skip this target, keep the others.
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
    _transport->queryAsync(
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

          self->_transport->queryAsync(
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
      if (!_cache)
      {
        continue;
      }

      DnsQuestion srvQuestion(srvTarget.srvName, DnsType::SRV, DnsClass::IN);
      DnsResult srvResult;
      if (_cache->get(srvQuestion, srvResult))
      {
        processSrvRecords(srvResult.srv_records, srvTarget.service, result, srvTarget.naptrPreference);
      }
    }

    // Step 3: Try to resolve hostnames from cache
    for (auto &target : result.targets)
    {
      if (!_cache)
      {
        continue;
      }

      // Try A records first
      DnsQuestion aQuestion(target.hostname, DnsType::A, DnsClass::IN);
      DnsResult aResult;
      if (_cache->get(aQuestion, aResult))
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
        if (_cache->get(aaaaQuestion, aaaaResult))
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
    if (!_cache)
    {
      return;
    }

    if (result.isSuccess())
    {
      _cache->put(question, result);
      return;
    }

    // Negative response: only cache it if it carries an SOA (RFC 2308 §5).
    if (!negativeResponseHasSoa(result))
    {
      return;
    }

    if (result.header.rcode == DnsResponseCode::NXDOMAIN)
    {
      _cache->putNegative(question, result, "Domain not found (NXDOMAIN)");
    }
    else if (result.header.rcode == DnsResponseCode::NOERROR)
    {
      // NODATA (NOERROR with no answer records) — RFC 2308 §2.2. Caching this
      // stops the common "name exists but no records of this type" case (e.g. a
      // domain publishing SRV but no NAPTR) from re-querying on every lookup.
      _cache->putNegative(question, result, "No records of requested type (NODATA)");
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

  /// \brief Order the failover list: per-owner-name transport sequencing, then RFC 2782
  ///        (priority, then weighted-random) WITHIN each owner name (2026-09-25-4).
  ///
  /// Outer sequencing key (owner-name-delimited): (naptrPreference/transport-rank, transport,
  /// priority). naptrPreference carries either the NAPTR preference tier (NAPTR path) or the
  /// per-set transport rank from buildOrderedSrvQueries (direct-SRV path) — mutually exclusive
  /// on one result. `transport` (the ServiceType) is the SRV owner-name discriminator, so
  /// priority is NEVER compared across owner names (RFC 2782 defines priority per RRSet).
  ///
  /// Within each equal-(tier, transport, priority) group the RFC 2782 weighted algorithm is
  /// applied to the LIST (not just a single pick): weight-0 records first in the arrangement,
  /// then repeated selection-without-replacement (recompute the remaining sum each step, draw
  /// uniform in [0, remaining-sum] inclusive, take the first cumulative sum >= the draw).
  ///
  /// RNG ownership: derive a per-call generator by ONE draw of the resolver's _rng under
  /// _rngMutex — advancing the master so successive/concurrent resolutions differ — then order
  /// UNLOCKED on the local generator. _rngMutex is a leaf lock (never held across a callback,
  /// never co-held with a result lock).
  void sortTargetsByPriority(ServiceResolutionResult &result)
  {
    std::stable_sort(result.targets.begin(), result.targets.end(),
                     [](const ServiceTarget &a, const ServiceTarget &b)
                     {
                       if (a.naptrPreference != b.naptrPreference)
                       {
                         return a.naptrPreference < b.naptrPreference;
                       }
                       if (a.transport != b.transport)
                       {
                         return a.transport < b.transport;
                       }
                       return a.priority < b.priority;
                     });

    // Nothing to weight-order with fewer than two targets — skip the RNG draw so master-stream
    // consumption tracks actual ordering work, not call count.
    if (result.targets.size() < 2)
    {
      return;
    }

    // Advance the master RNG once under the leaf lock, then order unlocked.
    std::mt19937 local;
    {
      std::lock_guard<std::mutex> lock(_rngMutex);
      local.seed(_rng());
    }
    applyWeightedOrdering(result.targets, local);
  }

  /// \brief Apply RFC 2782 weighted ordering to each contiguous equal-(naptrPreference,
  ///        transport, priority) run of an already-stable-sorted target list.
  static void applyWeightedOrdering(std::vector<ServiceTarget> &targets, std::mt19937 &rng)
  {
    std::size_t i = 0;
    while (i < targets.size())
    {
      std::size_t j = i + 1;
      while (j < targets.size() && targets[j].naptrPreference == targets[i].naptrPreference &&
             targets[j].transport == targets[i].transport &&
             targets[j].priority == targets[i].priority)
      {
        ++j;
      }
      if (j - i > 1)
      {
        weightedOrderGroup(targets, i, j, rng);
      }
      i = j;
    }
  }

  /// \brief RFC 2782 weighted-random ordering of one equal-priority owner-name group
  ///        (targets[begin, end)), in place. Selection WITHOUT replacement.
  static void weightedOrderGroup(std::vector<ServiceTarget> &targets, std::size_t begin,
                                 std::size_t end, std::mt19937 &rng)
  {
    // Working pool for the group. Arrange weight-0 records first (RFC 2782: "placed at the
    // beginning of the list ... in any order"), randomized among themselves so each gets a
    // fair share of the minimal selection chance.
    std::vector<ServiceTarget> pool(std::make_move_iterator(targets.begin() + begin),
                                    std::make_move_iterator(targets.begin() + end));
    std::stable_partition(pool.begin(), pool.end(),
                          [](const ServiceTarget &t) { return t.weight == 0; });
    auto zeroEnd = std::find_if(pool.begin(), pool.end(),
                                [](const ServiceTarget &t) { return t.weight != 0; });
    std::shuffle(pool.begin(), zeroEnd, rng);

    // Repeated running-sum selection: recompute the remaining sum each iteration (RFC 2782
    // selection-without-replacement), draw uniform in [0, remaining] INCLUSIVE, pick the first
    // cumulative sum >= the draw. Weight-0 records (running sum stays flat) win only on draw==0,
    // yielding the RFC "very small chance"; once only weight-0 remain (remaining==0) they are
    // emitted in their already-randomized order.
    std::size_t out = begin;
    while (!pool.empty())
    {
      std::uint32_t remaining = 0;
      for (const auto &t : pool)
      {
        remaining += t.weight;
      }

      std::size_t pick = 0;
      if (remaining != 0)
      {
        std::uniform_int_distribution<std::uint32_t> dist(0, remaining);
        std::uint32_t r = dist(rng);
        std::uint32_t running = 0;
        pick = pool.size() - 1; // unreachable default: running reaches `remaining` (== the draw's
                                // inclusive max) at the last element, so the scan always matches
        for (std::size_t k = 0; k < pool.size(); ++k)
        {
          running += pool[k].weight;
          if (running >= r)
          {
            pick = k;
            break;
          }
        }
      }

      targets[out++] = std::move(pool[pick]);
      pool.erase(pool.begin() + static_cast<std::ptrdiff_t>(pick));
    }
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
    _transport->queryAsync(
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

          self->_transport->queryAsync(aaaaQuestion,
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

      _transport->queryAsync(
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

            self->_transport->queryAsync(
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