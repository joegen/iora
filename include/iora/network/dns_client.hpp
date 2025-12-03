// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include "dns/dns_cache.hpp"
#include "dns/dns_message.hpp"
#include "dns/dns_resolver.hpp"
#include "dns/dns_transport.hpp"
#include "dns/dns_types.hpp"
#include "dns/dns_utils.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <functional>
#include <future>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace iora
{
namespace network
{

/// \brief Async DNS request handle for cancellation
///
/// Provides simple boolean cancellation interface for async DNS operations.
/// Uses atomic operations for thread-safety across multi-threaded callbacks.
class AsyncDnsRequest
{
public:
  /// \brief Default constructor (invalid request)
  AsyncDnsRequest() = default;

  /// \brief Cancel the DNS request (best-effort)
  ///
  /// Attempts to cancel the DNS request. Cancellation is best-effort and may not
  /// prevent callback delivery if the transport has already started processing.
  ///
  /// \return true if successfully cancelled, false if already completed or cancelled
  bool cancel()
  {
    if (!state_)
      return false;
    return !state_->cancelled.exchange(true, std::memory_order_acq_rel);
  }

  /// \brief Check if request was cancelled
  ///
  /// Note: Due to best-effort cancellation semantics, a cancelled request
  /// may still have its callback invoked if transport processing had already begun.
  ///
  /// \return true if cancelled
  bool isCancelled() const { return state_ && state_->cancelled.load(std::memory_order_acquire); }

  /// \brief Check if request completed
  /// \return true if completed (successfully or with error)
  bool isCompleted() const { return state_ && state_->completed.load(std::memory_order_acquire); }

  /// \brief Get hostname being queried
  /// \return hostname string, empty if invalid request
  std::string getHostname() const { return state_ ? state_->hostname : ""; }

  /// \brief Mark request as completed (for cancellation)
  /// \internal Used by CancellableFuture to update completion state
  void markCompleted()
  {
    if (state_)
    {
      state_->completed.store(true, std::memory_order_release);
    }
  }

private:
  friend class DnsClient;
  template <typename T> friend struct CancellableFuture;

  /// \brief Internal state shared between request handle and transport
  struct RequestState
  {
    std::atomic<bool> cancelled{false};
    std::atomic<bool> completed{false};
    std::atomic<bool> deliveryAttempted{false}; // Guards against double callback delivery
    std::string hostname;

    RequestState(std::string host) : hostname(std::move(host)) {}
  };

  /// \brief Constructor for valid request
  explicit AsyncDnsRequest(std::shared_ptr<RequestState> state) : state_(std::move(state)) {}

  std::shared_ptr<RequestState> state_;
};

/// \brief Future with cancellation support for DNS operations
///
/// Combines std::future with AsyncDnsRequest for cancellable future-based operations.
template <typename T> struct CancellableFuture
{
  std::future<T> future;
  AsyncDnsRequest request;
  std::shared_ptr<std::promise<T>> promise_;      // Store promise for immediate cancellation
  std::shared_ptr<std::atomic<bool>> promiseSet_; // Shared atomic guard

  /// \brief Cancel the underlying DNS request (immediate when safe)
  ///
  /// Attempts to cancel the DNS request. If cancellation is successful and no async
  /// operation has delivered results yet, immediately sets the promise to wake waiting
  /// threads. Uses atomic guards to prevent race conditions with callbacks.
  ///
  /// \return true if successfully cancelled
  bool cancel()
  {
    bool cancelResult = request.cancel();

    if (cancelResult && promise_)
    {
      // Use promiseSet atomic guard to prevent race with callback
      if (promiseSet_)
      {
        bool expected = false;
        if (promiseSet_->compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
          try
          {
            promise_->set_exception(
              std::make_exception_ptr(dns::DnsResolverException("DNS request cancelled")));
          }
          catch (const std::future_error &)
          {
            // Promise already set - should not happen due to atomic guard
          }
        }
      }
      // Always mark as completed if cancellation succeeded
      request.markCompleted();
    }

    return cancelResult;
  }

  /// \brief Check if request was cancelled
  bool isCancelled() const { return request.isCancelled(); }

  /// \brief Check if request completed
  bool isCompleted() const { return request.isCompleted(); }

  /// \brief Get hostname being queried
  std::string getHostname() const { return request.getHostname(); }
};

/// \brief Factory function for creating cancellable futures
/// \param future The std::future to wrap
/// \param request The AsyncDnsRequest handle
/// \param promise The promise for immediate cancellation
/// \param promiseSet The atomic guard for promise setting
/// \return CancellableFuture combining both
template <typename T>
CancellableFuture<T>
make_cancellable_future(std::future<T> &&future, AsyncDnsRequest &&request,
                        std::shared_ptr<std::promise<T>> promise = nullptr,
                        std::shared_ptr<std::atomic<bool>> promiseSet = nullptr)
{
  return CancellableFuture<T>{std::move(future), std::move(request), promise, promiseSet};
}

/// \brief Complete DNS client with RFC 3263 service discovery
///
/// This is the main public API for DNS operations in the Iora framework.
/// It provides both basic DNS queries and generic service discovery
/// following RFC 3263 procedures. The client supports:
///
/// - Standard DNS queries (A, AAAA, CNAME, MX, TXT, PTR, SRV, NAPTR)
/// - Service discovery (NAPTR -> SRV -> A/AAAA chain resolution) for SIP, HTTP, etc.
/// - Intelligent caching with TTL awareness
/// - UDP/TCP transport with automatic fallback
/// - Synchronous and asynchronous operation modes
/// - Rich exception-based error reporting
///
/// Example usage:
/// \code
/// // Create client with default configuration
/// DnsClient client;
///
/// // Resolve service domain (SIP example)
/// auto serviceResult = client.resolveServiceDomain("example.com");
/// for (const auto& target : serviceResult.targets) {
///   std::cout << target.hostname << ":" << target.port
///             << " (" << target.getTransportString() << ")\n";
/// }
///
/// // Standard DNS query
/// auto aRecords = client.resolveA("www.example.com");
/// for (const auto& addr : aRecords) {
///   std::cout << "IP: " << addr << "\n";
/// }
/// \endcode
class DnsClient
{
public:
  /// \brief Default constructor with standard configuration
  DnsClient() : DnsClient(dns::DnsConfig{}) {}

  /// \brief Constructor with custom configuration
  /// \param config DNS client configuration
  explicit DnsClient(const dns::DnsConfig &config) : config_(config) { initialize(); }

  /// \brief Constructor with custom transport (for testing)
  /// \param transport Custom transport implementation
  /// \param config DNS client configuration
  explicit DnsClient(std::shared_ptr<UnifiedSharedTransport> transport,
                     const dns::DnsConfig &config = dns::DnsConfig{})
      : config_(config), customTransport_(transport)
  {
    initialize();
  }

  /// \brief Destructor - stops transport automatically
  ~DnsClient()
  {
    // Transport stop is handled automatically by dns::DnsTransport destructor
    // No explicit action needed - RAII pattern
  }

  /// \brief Start the DNS client (compatibility method)
  /// \return Always returns true - transport is started in constructor
  bool start() { return true; }

  /// \brief Stop the DNS client (compatibility method)
  /// Cleanup handled by destructor
  void stop() { /* No explicit action needed - RAII */ }

  /// \brief Resolve hostname to IP addresses (compatibility method)
  /// \param hostname Hostname to resolve
  /// \return HostResult with IPv4 and IPv6 addresses
  struct HostResult
  {
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
    bool success = false;
  };

  HostResult resolveHost(const std::string &hostname)
  {
    HostResult result;

    // Resolve A records (IPv4) - failure should not prevent IPv6 resolution
    try
    {
      result.ipv4 = resolveA(hostname);
    }
    catch (...)
    {
      // IPv4 resolution failed, continue with IPv6
    }

    // Resolve AAAA records (IPv6) - failure should not discard IPv4 results
    try
    {
      result.ipv6 = resolveAAAA(hostname);
    }
    catch (...)
    {
      // IPv6 resolution failed, continue with IPv4 results
    }

    result.success = !result.ipv4.empty() || !result.ipv6.empty();
    return result;
  }

  // Disable copy constructor and assignment operator
  DnsClient(const DnsClient &) = delete;
  DnsClient &operator=(const DnsClient &) = delete;

  // Enable move constructor and assignment operator
  DnsClient(DnsClient &&) = default;
  DnsClient &operator=(DnsClient &&) = default;

  // =============================================================================
  // Service Discovery Methods (RFC 3263 NAPTR→SRV→A/AAAA chain)
  // =============================================================================

  /// \brief Resolve service domain using RFC 3263 procedure
  /// \param domain Service domain to resolve (e.g., "example.com", "sip.example.org")
  /// \param preferredTransports Preferred transport types in order of preference
  /// \return Service resolution result with prioritized targets
  /// \throws dns::DnsResolverException on resolution failure
  dns::ServiceResolutionResult
  resolveServiceDomain(const std::string &domain,
                       const std::vector<dns::ServiceType> &preferredTransports = {})
  {
    return resolver_->resolveServiceDomain(domain, preferredTransports);
  }

  /// \brief Resolve custom service domain with specific SRV record queries
  /// \param domain Service domain to resolve (e.g., "example.com")
  /// \param srvQueries Custom SRV queries to try (e.g., {{"_xmpp-client._tcp.example.com",
  /// dns::ServiceType::TCP}})
  /// \param preferredTransports Preferred transport types in order of preference
  /// \return Service resolution result with prioritized targets
  /// \throws dns::DnsResolverException on resolution failure
  dns::ServiceResolutionResult resolveCustomServiceDomain(
    const std::string &domain,
    const std::vector<std::pair<std::string, dns::ServiceType>> &srvQueries,
    const std::vector<dns::ServiceType> &preferredTransports = {})
  {
    return resolver_->performDirectSrvResolution(domain, preferredTransports,
                                                 std::make_optional(srvQueries));
  }

  /// \brief Resolve service domain asynchronously
  /// \param domain Service domain to resolve
  /// \param callback Callback function for result notification
  /// \param preferredTransports Preferred transport types in order of preference
  void resolveServiceDomainAsync(const std::string &domain,
                                 dns::DnsResolver::ServiceResolutionCallback callback,
                                 const std::vector<dns::ServiceType> &preferredTransports = {})
  {
    resolver_->resolveServiceDomainAsync(domain, callback, preferredTransports);
  }

  /// \brief Resolve custom service domain asynchronously
  /// \param domain Service domain to resolve
  /// \param srvQueries Custom SRV queries to try
  /// \param callback Callback function for result notification
  /// \param preferredTransports Preferred transport types in order of preference
  void resolveCustomServiceDomainAsync(
    const std::string &domain,
    const std::vector<std::pair<std::string, dns::ServiceType>> &srvQueries,
    dns::DnsResolver::ServiceResolutionCallback callback,
    const std::vector<dns::ServiceType> &preferredTransports = {})
  {
    resolver_->performDirectSrvResolutionAsync(domain, callback, preferredTransports,
                                               std::make_optional(srvQueries));
  }

  /// \brief Resolve service domain and return future
  /// \param domain Service domain to resolve
  /// \param preferredTransports Preferred transport types in order of preference
  /// \return CancellableFuture containing service resolution result
  CancellableFuture<dns::ServiceResolutionResult>
  resolveServiceDomainFuture(const std::string &domain,
                             const std::vector<dns::ServiceType> &preferredTransports = {})
  {
    auto state = std::make_shared<AsyncDnsRequest::RequestState>(domain);
    auto promise = std::make_shared<std::promise<dns::ServiceResolutionResult>>();
    auto promiseSet = std::make_shared<std::atomic<bool>>(false);
    auto future = promise->get_future();

    // Create async request handle
    AsyncDnsRequest request(state);

    resolveServiceDomainAsync(
      domain,
      [promise, promiseSet, state](const dns::ServiceResolutionResult &result, const std::exception_ptr &ex)
      {
        // Atomic guard against double-set
        bool expected = false;
        if (!promiseSet->compare_exchange_strong(expected, true,
                                                  std::memory_order_acq_rel))
        {
          return; // Promise already set by cancellation or another callback
        }

        // Check for cancellation after securing delivery guard
        if (state->cancelled.load(std::memory_order_acquire))
        {
          try
          {
            promise->set_exception(
              std::make_exception_ptr(dns::DnsResolverException("DNS request cancelled")));
          }
          catch (const std::future_error &)
          {
            // Promise already set - ignore
          }
          state->completed.store(true, std::memory_order_release);
          return;
        }

        try
        {
          if (ex)
          {
            promise->set_exception(ex);
          }
          else
          {
            promise->set_value(result);
          }
        }
        catch (const std::future_error &)
        {
          // Promise already set - ignore
        }

        // Set completion flag after processing callback
        state->completed.store(true, std::memory_order_release);
      },
      preferredTransports);

    return make_cancellable_future(std::move(future), std::move(request), promise, promiseSet);
  }

  // =============================================================================
  // Standard DNS Query Methods
  // =============================================================================

  /// \brief Perform generic DNS query
  /// \param question DNS question to resolve
  /// \return DNS query result
  /// \throws dns::DnsResolverException on query failure
  dns::DnsResult query(const dns::DnsQuestion &question) { return resolver_->query(question); }

  /// \brief Perform DNS query asynchronously
  /// \param question DNS question to resolve
  /// \param callback Callback function for result notification
  void queryAsync(const dns::DnsQuestion &question,
                  std::function<void(const dns::DnsResult &, const std::exception_ptr &)> callback)
  {
    resolver_->queryAsync(question, callback);
  }

  /// \brief Resolve A records synchronously (IPv4 addresses)
  /// \param hostname Hostname to resolve
  /// \return Vector of IPv4 address strings
  /// \throws dns::DnsResolverException on resolution failure
  std::vector<std::string> resolveA(const std::string &hostname)
  {
    dns::DnsResult result = query(dns::DnsQuestion(hostname, dns::DnsType::A, dns::DnsClass::IN));

    std::vector<std::string> addresses;
    for (const auto &record : result.a_records)
    {
      addresses.push_back(record.address);
    }

    if (addresses.empty())
    {
      throw dns::DnsNoRecordsException(hostname, dns::DnsType::A);
    }

    return addresses;
  }

  /// \brief Resolve A records asynchronously (IPv4 addresses) - PRIMARY API
  /// \param hostname Hostname to resolve
  /// \param callback Callback function called on completion or error
  /// \return AsyncDnsRequest for cancellation
  ///
  /// \warning Callback may execute on different threads:
  ///          - Immediate errors: caller thread
  ///          - Network responses: transport thread
  ///          - Timeouts: timer thread
  /// \warning Client must ensure thread-safe callback implementation
  AsyncDnsRequest
  resolveA(const std::string &hostname,
           std::function<void(std::vector<std::string>, std::exception_ptr)> callback);

  /// \brief Resolve A records asynchronously with cancellable future wrapper
  /// \param hostname Hostname to resolve
  /// \return CancellableFuture containing vector of IPv4 address strings and cancellation handle
  CancellableFuture<std::vector<std::string>> resolveAAsync(const std::string &hostname)
  {
    auto promise = std::make_shared<std::promise<std::vector<std::string>>>();
    auto promiseSet = std::make_shared<std::atomic<bool>>(false);
    auto future = promise->get_future();

    auto request = resolveA(
      hostname,
      [promise, promiseSet, hostname](std::vector<std::string> addresses, std::exception_ptr error)
      {
        // Atomic guard against double-set
        bool expected = false;
        if (!promiseSet->compare_exchange_strong(expected, true, std::memory_order_acq_rel))
        {
          return; // Promise already set by cancellation or another callback
        }

        try
        {
          if (error)
          {
            promise->set_exception(error);
          }
          else
          {
            promise->set_value(std::move(addresses));
          }
        }
        catch (const std::future_error &)
        {
          // Ignore double-set errors (defensive programming)
          // This shouldn't happen due to atomic guard above, but handle gracefully
        }
      });

    return make_cancellable_future(std::move(future), std::move(request), promise, promiseSet);
  }

  /// \brief Resolve AAAA records (IPv6 addresses)
  /// \param hostname Hostname to resolve
  /// \return Vector of IPv6 address strings
  /// \throws dns::DnsResolverException on resolution failure
  std::vector<std::string> resolveAAAA(const std::string &hostname)
  {
    dns::DnsResult result =
      query(dns::DnsQuestion(hostname, dns::DnsType::AAAA, dns::DnsClass::IN));

    std::vector<std::string> addresses;
    for (const auto &record : result.aaaa_records)
    {
      addresses.push_back(record.address);
    }

    if (addresses.empty())
    {
      throw dns::DnsNoRecordsException(hostname, dns::DnsType::AAAA);
    }

    return addresses;
  }

  /// \brief Resolve hostname to IP addresses (both IPv4 and IPv6)
  /// \param hostname Hostname to resolve
  /// \param prefer_ipv6 Prefer IPv6 addresses if available
  /// \return Vector of IP address strings
  /// \throws dns::DnsResolverException on resolution failure
  std::vector<std::string> resolveHostname(const std::string &hostname, bool prefer_ipv6 = false)
  {
    return resolver_->resolveHostname(hostname, prefer_ipv6);
  }

  /// \brief Resolve SRV records
  /// \param service Service name (e.g., "_sip._tcp.example.com")
  /// \return Vector of SRV records
  /// \throws dns::DnsResolverException on resolution failure
  std::vector<dns::SrvRecord> resolveSRV(const std::string &service)
  {
    dns::DnsResult result = query(dns::DnsQuestion(service, dns::DnsType::SRV, dns::DnsClass::IN));

    if (result.srv_records.empty())
    {
      throw dns::DnsNoRecordsException(service, dns::DnsType::SRV);
    }

    return result.srv_records;
  }

  /// \brief Resolve NAPTR records
  /// \param domain Domain name to query
  /// \return Vector of NAPTR records
  /// \throws dns::DnsResolverException on resolution failure
  std::vector<dns::NaptrRecord> resolveNAPTR(const std::string &domain)
  {
    dns::DnsResult result = query(dns::DnsQuestion(domain, dns::DnsType::NAPTR, dns::DnsClass::IN));

    if (result.naptr_records.empty())
    {
      throw dns::DnsNoRecordsException(domain, dns::DnsType::NAPTR);
    }

    return result.naptr_records;
  }

  /// \brief Resolve CNAME records
  /// \param hostname Hostname to resolve
  /// \return Vector of canonical names
  /// \throws dns::DnsResolverException on resolution failure
  std::vector<std::string> resolveCNAME(const std::string &hostname)
  {
    dns::DnsResult result =
      query(dns::DnsQuestion(hostname, dns::DnsType::CNAME, dns::DnsClass::IN));

    std::vector<std::string> names;
    for (const auto &record : result.cname_records)
    {
      names.push_back(record.cname);
    }

    if (names.empty())
    {
      throw dns::DnsNoRecordsException(hostname, dns::DnsType::CNAME);
    }

    return names;
  }

  /// \brief Resolve MX records
  /// \param domain Domain name to query
  /// \return Vector of MX records
  /// \throws dns::DnsResolverException on resolution failure
  std::vector<dns::MxRecord> resolveMX(const std::string &domain)
  {
    dns::DnsResult result = query(dns::DnsQuestion(domain, dns::DnsType::MX, dns::DnsClass::IN));

    if (result.mx_records.empty())
    {
      throw dns::DnsNoRecordsException(domain, dns::DnsType::MX);
    }

    return result.mx_records;
  }

  /// \brief Resolve TXT records
  /// \param domain Domain name to query
  /// \return Vector of TXT records
  /// \throws dns::DnsResolverException on resolution failure
  std::vector<dns::TxtRecord> resolveTXT(const std::string &domain)
  {
    dns::DnsResult result = query(dns::DnsQuestion(domain, dns::DnsType::TXT, dns::DnsClass::IN));

    if (result.txt_records.empty())
    {
      throw dns::DnsNoRecordsException(domain, dns::DnsType::TXT);
    }

    return result.txt_records;
  }

  /// \brief Resolve PTR records (reverse DNS)
  /// \param ip IP address to reverse resolve
  /// \return Vector of hostnames
  /// \throws dns::DnsResolverException on resolution failure
  std::vector<std::string> resolvePTR(const std::string &ip)
  {
    std::string reverseQuery = createReverseQuery(ip);
    dns::DnsResult result =
      query(dns::DnsQuestion(reverseQuery, dns::DnsType::PTR, dns::DnsClass::IN));

    std::vector<std::string> hostnames;
    for (const auto &record : result.ptr_records)
    {
      hostnames.push_back(record.ptrdname);
    }

    if (hostnames.empty())
    {
      throw dns::DnsNoRecordsException(ip, dns::DnsType::PTR);
    }

    return hostnames;
  }

  // =============================================================================
  // Cache Management
  // =============================================================================

  /// \brief Get cache statistics
  /// \return Current cache statistics (empty if caching disabled)
  dns::DnsCacheStats getCacheStats() const
  {
    if (cache_)
    {
      return cache_->getStats();
    }
    return dns::DnsCacheStats{};
  }

  /// \brief Clear DNS cache
  void clearCache()
  {
    if (cache_)
    {
      cache_->clear();
    }
  }

  /// \brief Remove specific entry from cache
  /// \param question DNS question to remove from cache
  void removeCacheEntry(const dns::DnsQuestion &question)
  {
    if (cache_)
    {
      cache_->remove(question);
    }
  }

  /// \brief Force cache cleanup (remove expired entries)
  /// \return Number of entries removed
  std::size_t cleanupCache()
  {
    if (cache_)
    {
      return cache_->cleanupExpired();
    }
    return 0;
  }

  // =============================================================================
  // Backward Compatibility Methods (SIP-specific names)
  // =============================================================================

  /// \brief Resolve SIP domain using RFC 3263 procedure
  /// \deprecated Use resolveServiceDomain() instead for broader applicability
  /// \param domain SIP domain to resolve (e.g., "example.com")
  /// \param preferredTransports Preferred transport types in order of preference
  /// \return SIP resolution result with prioritized targets
  /// \throws dns::DnsResolverException on resolution failure
  dns::SipResolutionResult
  resolveSipDomain(const std::string &domain,
                   const std::vector<dns::SipServiceType> &preferredTransports = {})
  {
    return resolveServiceDomain(domain, preferredTransports);
  }

  /// \brief Resolve SIP domain asynchronously
  /// \deprecated Use resolveServiceDomainAsync() instead for broader applicability
  /// \param domain SIP domain to resolve
  /// \param callback Callback function for result notification
  /// \param preferredTransports Preferred transport types in order of preference
  void resolveSipDomainAsync(
    const std::string &domain,
    std::function<void(const dns::SipResolutionResult &, const std::exception_ptr &)> callback,
    const std::vector<dns::SipServiceType> &preferredTransports = {})
  {
    resolveServiceDomainAsync(domain, callback, preferredTransports);
  }

  /// \brief Check if caching is enabled
  /// \return true if caching is enabled
  bool isCacheEnabled() const { return cache_ != nullptr; }

  // =============================================================================
  // Configuration and Status
  // =============================================================================

  /// \brief Get current DNS configuration
  /// \return Current configuration
  const dns::DnsConfig &getConfig() const { return config_; }

  /// \brief Update DNS configuration
  /// \param config New configuration
  /// \note This will recreate transport and resolver with new settings
  void updateConfig(const dns::DnsConfig &config)
  {
    config_ = config;
    initialize(); // Reinitialize with new config
  }

  /// \brief Set DNS servers (replaces all existing servers)
  /// \param servers List of DNS server addresses (e.g., {"8.8.8.8", "1.1.1.1:53", "2001:4860:4860::8888"})
  /// \note Servers without explicit port use default port 53. IPv6 addresses supported.
  void setDnsServers(const std::vector<std::string> &servers)
  {
    config_.setServers(servers);
    initialize(); // Reinitialize with new servers
  }

  /// \brief Add DNS server to configuration
  /// \param server DNS server in "address" or "address:port" format
  void addDnsServer(const std::string &server)
  {
    // Parse server string to DnsServer structure
    dns::DnsServer dnsServer = dns::DnsServer::fromString(server);

    // Check if server already exists
    auto &servers = config_.servers;
    if (std::find(servers.begin(), servers.end(), dnsServer) == servers.end())
    {
      servers.push_back(dnsServer);
      initialize(); // Reinitialize with new servers
    }
  }

  /// \brief Remove DNS server from configuration
  /// \param server DNS server in "address" or "address:port" format to remove
  void removeDnsServer(const std::string &server)
  {
    // Parse server string to DnsServer structure
    dns::DnsServer dnsServer = dns::DnsServer::fromString(server);

    auto &servers = config_.servers;
    servers.erase(std::remove(servers.begin(), servers.end(), dnsServer), servers.end());

    if (servers.empty())
    {
      // Restore defaults if all servers removed
      servers = {dns::DnsServer("8.8.8.8", 53), dns::DnsServer("1.1.1.1", 53)};
    }

    initialize(); // Reinitialize with updated servers
  }

  /// \brief Get list of configured DNS servers
  /// \return Vector of DNS server addresses in "address:port" format
  std::vector<std::string> getDnsServers() const
  {
    std::vector<std::string> result;
    result.reserve(config_.servers.size());
    for (const auto &server : config_.servers)
    {
      result.push_back(server.toString());
    }
    return result;
  }

  /// \brief Set cache cleanup callback for monitoring
  /// \param callback Function to call after cache cleanup operations
  void setCacheCleanupCallback(std::function<void(const dns::DnsCacheStats &)> callback)
  {
    if (cache_)
    {
      cache_->setCleanupCallback(callback);
    }
  }

private:
  dns::DnsConfig config_;                                   ///< DNS configuration
  std::shared_ptr<UnifiedSharedTransport> customTransport_; ///< Custom transport (optional)
  std::shared_ptr<dns::DnsTransport> transport_;            ///< DNS transport layer
  std::shared_ptr<dns::DnsCache> cache_;                    ///< DNS cache (optional)
  std::shared_ptr<dns::DnsResolver> resolver_;              ///< DNS resolver

  /// \brief Initialize all DNS components based on current configuration
  void initialize()
  {
    // DnsServer structure already handles normalization via fromString()
    // No additional normalization needed

    // Create cache if enabled
    if (config_.enableCache)
    {
      cache_ = std::make_shared<dns::DnsCache>(config_.maxCacheSize);
    }
    else
    {
      cache_.reset();
    }

    // Create transport layer
    transport_ = std::make_shared<dns::DnsTransport>(config_);

    // Create resolver
    resolver_ = std::make_shared<dns::DnsResolver>(transport_, cache_, config_);

    // Start the transport - this is required for dns::DnsTransport::query() to work
    try
    {
      transport_->start();
    }
    catch (const std::exception &e)
    {
      throw dns::DnsResolverException("Failed to start DNS transport: " + std::string(e.what()));
    }
  }

  /// \brief Create IPv6 reverse DNS query string (ip6.arpa)
  /// \param ipv6 IPv6 address string
  /// \return Reverse DNS query string for IPv6
  std::string createIpv6ReverseQuery(const std::string &ipv6) const
  {
    // Normalize IPv6 address - remove brackets and expand to full form
    std::string addr = ipv6;

    // Remove brackets if present
    if (addr.front() == '[' && addr.back() == ']')
    {
      addr = addr.substr(1, addr.length() - 2);
    }

    // Split on '%' to remove zone ID if present
    size_t zone_pos = addr.find('%');
    if (zone_pos != std::string::npos)
    {
      addr = addr.substr(0, zone_pos);
    }

    // Expand IPv6 address to full 32-character hex representation
    std::string expanded = expandIpv6Address(addr);

    // Convert to nibble-reversed format for ip6.arpa
    std::string result;
    for (int i = 31; i >= 0; --i) // Reverse order of nibbles
    {
      result += expanded[i];
      result += '.';
    }
    result += "ip6.arpa";

    return result;
  }

  /// \brief Expand IPv6 address to full 32-character hex representation
  /// \param ipv6 IPv6 address string (without brackets or zone)
  /// \return 32-character lowercase hex string
  std::string expandIpv6Address(const std::string &ipv6) const
  {
    std::vector<std::string> groups;
    std::string expanded;

    // Handle :: expansion
    size_t double_colon = ipv6.find("::");
    if (double_colon != std::string::npos)
    {
      std::string left = ipv6.substr(0, double_colon);
      std::string right = ipv6.substr(double_colon + 2);

      // Count existing groups
      int left_groups = left.empty() ? 0 : std::count(left.begin(), left.end(), ':') + 1;
      int right_groups = right.empty() ? 0 : std::count(right.begin(), right.end(), ':') + 1;
      int missing_groups = 8 - left_groups - right_groups;

      // Build expanded form
      if (!left.empty())
        expanded = left + ":";
      for (int i = 0; i < missing_groups; ++i)
      {
        expanded += "0000:";
      }
      if (!right.empty())
        expanded += right;
      else
        expanded.pop_back(); // Remove trailing ':'
    }
    else
    {
      expanded = ipv6;
    }

    // Parse groups and pad to 4 hex digits each
    std::stringstream ss(expanded);
    std::string group;
    std::string result;

    while (std::getline(ss, group, ':'))
    {
      // Pad to 4 characters with leading zeros
      while (group.length() < 4)
      {
        group = "0" + group;
      }
      // Convert to lowercase
      std::transform(group.begin(), group.end(), group.begin(), ::tolower);
      result += group;
    }

    if (result.length() != 32)
    {
      throw dns::DnsResolverException("Invalid IPv6 address format: " + ipv6);
    }

    return result;
  }

  /// \brief Create reverse DNS query string from IP address
  /// \param ip IP address (IPv4 or IPv6)
  /// \return Reverse DNS query string
  std::string createReverseQuery(const std::string &ip) const
  {
    // Detect IPv4 vs IPv6
    if (ip.find(':') != std::string::npos)
    {
      // IPv6 reverse query (ip6.arpa) - convert to nibble-reversed format
      return createIpv6ReverseQuery(ip);
    }
    else
    {
      // IPv4 reverse query (in-addr.arpa)
      std::vector<std::string> octets;
      std::stringstream ss(ip);
      std::string octet;

      while (std::getline(ss, octet, '.'))
      {
        octets.push_back(octet);
      }

      if (octets.size() != 4)
      {
        throw dns::DnsResolverException("Invalid IPv4 address for reverse query: " + ip);
      }

      // Reverse the octets and append .in-addr.arpa
      return octets[3] + "." + octets[2] + "." + octets[1] + "." + octets[0] + ".in-addr.arpa";
    }
  }

  /// \brief Internal implementation of async A record resolution
  /// \pre transport_ must be valid (checked by caller)
  /// \pre state must be valid (provided by caller)
  void resolveAInternal(const std::string &hostname,
                        std::function<void(std::vector<std::string>, std::exception_ptr)> callback,
                        std::shared_ptr<AsyncDnsRequest::RequestState> state)
  {
    dns::DnsQuestion question(hostname, dns::DnsType::A, dns::DnsClass::IN);

    transport_->queryAsync(
      question,
      [callback = std::move(callback), state](const dns::DnsResult &result,
                                              std::exception_ptr error) mutable
      {
        // Atomic delivery guard - only first caller proceeds
        bool expectedDelivery = false;
        if (!state->deliveryAttempted.compare_exchange_strong(expectedDelivery, true,
                                                              std::memory_order_acq_rel))
        {
          return; // Already delivered or being delivered by another thread
        }

        // Check cancellation after securing delivery slot
        if (state->cancelled.load(std::memory_order_acquire))
        {
          // Invoke callback with cancellation exception to prevent future hanging
          callback({}, std::make_exception_ptr(dns::DnsResolverException("DNS request cancelled")));
          state->completed.store(true, std::memory_order_release);
          return;
        }

        // Process result and invoke callback
        try
        {
          if (error)
          {
            callback({}, error);
          }
          else
          {
            std::vector<std::string> addresses;
            for (const auto &record : result.a_records)
            {
              addresses.push_back(record.address);
            }

            if (addresses.empty())
            {
              auto noRecordsError = std::make_exception_ptr(
                dns::DnsNoRecordsException(state->hostname, dns::DnsType::A));
              callback({}, noRecordsError);
            }
            else
            {
              callback(std::move(addresses), nullptr);
            }
          }
        }
        catch (...)
        {
          callback({}, std::current_exception());
        }

        // Mark completed after callback processing
        state->completed.store(true, std::memory_order_release);
      });
  }
};

// =============================================================================
// ASYNC API IMPLEMENTATIONS
// =============================================================================

inline AsyncDnsRequest
DnsClient::resolveA(const std::string &hostname,
                    std::function<void(std::vector<std::string>, std::exception_ptr)> callback)
{
  // Create request state for cancellation tracking
  auto state = std::make_shared<AsyncDnsRequest::RequestState>(hostname);

  // Check for immediate errors
  if (!transport_)
  {
    auto error =
      std::make_exception_ptr(dns::DnsResolverException("DNS transport not initialized"));
    callback({}, error);
    return AsyncDnsRequest{}; // Return invalid request
  }

  try
  {
    // Start async resolution
    resolveAInternal(hostname, std::move(callback), state);

    // Return cancellable request handle
    return AsyncDnsRequest(state);
  }
  catch (...)
  {
    // Immediate error - call callback on caller thread
    callback({}, std::current_exception());
    return AsyncDnsRequest{}; // Return invalid request
  }
}

} // namespace network
} // namespace iora