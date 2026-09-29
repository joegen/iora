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
#include <atomic>
#include <cassert>
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

/// \brief Generic "secure transport" predicate — the single source of truth for
/// ServiceTarget::isSecure(). Includes HTTPS_TCP (secure but non-SIP), so it is
/// NOT suitable for the RFC 3263 §4.1 SIPS discard — use isSecureSipService for that.
/// Declared before ServiceTarget so its inline isSecure() body can call it.
inline bool isSecureService(ServiceType transport)
{
  return transport == ServiceType::SIPS_TLS || transport == ServiceType::SIPS_SCTP ||
         transport == ServiceType::SIPS_WSS || transport == ServiceType::HTTPS_TCP;
}

/// \brief SIP-scoped secure predicate (SIPS_TLS/SIPS_SCTP/SIPS_WSS only, EXCLUDES
/// HTTPS_TCP). RFC 3263 §4.1 requires the service-field protocol to be SIPS, so a
/// secure SIP resolution must discard non-SIP encrypted services (e.g. HTTPS+D2T).
/// This is the predicate every secure §4.1 discard/filter uses.
inline bool isSecureSipService(ServiceType transport)
{
  return transport == ServiceType::SIPS_TLS || transport == ServiceType::SIPS_SCTP ||
         transport == ServiceType::SIPS_WSS;
}

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

  /// \brief Check if this is a secure transport (generic; delegates to the single
  /// source of truth isSecureService — includes HTTPS_TCP).
  bool isSecure() const { return isSecureService(transport); }
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

/// \brief Per-avenue transient-vs-permanent classification of a resolution outcome
///        (tracker 2026-09-25-8, Slice A). ADDITIVE: isSuccess() (= !targets.empty())
///        callers are unchanged; a consumer that needs the retryable/no-service
///        distinction (e.g. iora_sip SipDnsAdapter, mapping a transient outage to a
///        503 vs a permanent no-service to a 404) opts in by reading `outcome`.
///
/// SLICE-A SEMANTICS (per-avenue only): a SINGLE resolution avenue — one query()
/// leaf, one resolveHostname, or one direct-SRV — sets its own outcome at its terminal:
///   - targets non-empty                                   => Resolved
///   - all servers rotated, still server-local/timeout      => TransientFailure
///   - authoritative negative (NXDOMAIN / NODATA-with-SOA)  => PermanentNoService
/// The CROSS-STEP combination across the RFC 3263 NAPTR→SRV→A/AAAA fall-forward chain
/// (deepest-avenue-supersedes) is a SEPARATE slice (tracker 2026-09-30-1). Interim: a
/// multi-step resolveServiceDomain carries the TERMINAL avenue's per-avenue outcome.
enum class ResolutionOutcome
{
  Resolved,          ///< Targets were produced (isSuccess()==true).
  TransientFailure,  ///< Server-local/timeout exhausted across all servers — RETRYABLE.
  PermanentNoService ///< Authoritative negative (NXDOMAIN / NODATA-with-SOA) — no service.
};

/// \brief Service resolution result with prioritized targets
/// Follows RFC 3263 NAPTR→SRV→A/AAAA resolution chain
struct ServiceResolutionResult
{
  std::vector<ServiceTarget> targets;              ///< Resolved targets (priority sorted)
  std::string domain;                              ///< Original domain queried
  bool fromCache{false};                           ///< Whether result came from cache
  std::chrono::steady_clock::time_point timestamp; ///< Resolution timestamp
  ResolutionOutcome outcome{ResolutionOutcome::Resolved}; ///< Per-avenue transient/permanent
                                                          ///< classification (Slice A). Default
                                                          ///< Resolved keeps existing callers
                                                          ///< source-compatible.

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

/// \brief Thrown by query()'s next-server failover loop when ALL configured servers are
///        exhausted on SERVER-LOCAL conditions (SERVFAIL/REFUSED/FORMERR/NOTIMP/
///        NODATA-without-SOA/timeout/network fault) without ever reaching an authoritative
///        response or a success (tracker 2026-09-25-8).
///
/// Distinct TYPE from DnsResolutionFailedException / DnsNoRecordsException (which mark an
/// AUTHORITATIVE negative — NXDOMAIN / NODATA-with-SOA). It derives from DnsResolverException
/// so every existing `catch (const DnsResolverException&)` (including the RFC 3263 step-fallback
/// handlers) still catches it; resolveHostname catches it FIRST to preserve the transient
/// (retryable) vs permanent (no-service) distinction across its throwing return channel.
class DnsTransientResolutionException : public DnsResolverException
{
public:
  explicit DnsTransientResolutionException(const std::string &domain,
                                           DnsResponseCode code = DnsResponseCode::SERVFAIL)
      : DnsResolverException("Transient DNS failure (all servers exhausted) for: " + domain, code)
  {
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
  /// \param secure RFC 3263 §4.1 SIPS SIP-secure resolution: when true, every path
  ///        discards non-SIPS-SIP services (isSecureSipService) and the A/AAAA fallback
  ///        defaults to TLS/5061. This means SIP-secure, NOT generic transport security
  ///        (HTTPS_TCP targets are discarded). Defaulted false; the SIP layer
  ///        (iora_sip SipDnsAdapter) drives it true for a sips: URI.
  /// \return Service resolution result with prioritized targets
  /// \throws DnsResolverException on resolution failure
  ServiceResolutionResult
  resolveServiceDomain(const std::string &domain,
                       const std::vector<ServiceType> &preferredTransports = {},
                       bool secure = false)
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
        processCachedServiceResolution(result, naptrResult, preferredTransports, secure);
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

    auto result = performServiceResolution(domain, preferredTransports, secure);

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
  /// \param secure RFC 3263 §4.1 SIPS SIP-scoped secure resolution (non-SIPS-SIP services,
  ///        incl. HTTPS, are discarded; A/AAAA fallback defaults to TLS/5061); NOT generic
  ///        transport security. Defaulted false; the SIP layer drives it true for sips:.
  void resolveServiceDomainAsync(const std::string &domain, ServiceResolutionCallback callback,
                                 const std::vector<ServiceType> &preferredTransports = {},
                                 bool secure = false)
  {
    // Deliver AT MOST ONCE across every path below (cache-hit, fresh, and any TS-M2
    // re-delivery on a throwing callback) -- tracker 2026-09-25-5 steps-4-8 H-1.
    callback = makeSingleFire(std::move(callback));

    // Check cache first
    if (_cache)
    {
      DnsQuestion naptrQuestion(domain, DnsType::NAPTR, DnsClass::IN);
      DnsResult naptrResult;
      if (_cache->get(naptrQuestion, naptrResult))
      {
        iora::core::Logger::debug("DNS async service resolution cache hit for domain: " + domain);
        ServiceResolutionResult cachedResult(domain);
        bool cachedOk = false;
        try
        {
          cachedResult.fromCache = true;
          processCachedServiceResolution(cachedResult, naptrResult, preferredTransports, secure);
          cachedOk = cachedResult.isSuccess();
          if (!cachedOk)
          {
            iora::core::Logger::debug(
              "DNS cached async service resolution incomplete for domain: " + domain);
          }
        }
        catch (...)
        {
          iora::core::Logger::debug("DNS cached async service resolution error for domain: " +
                                    domain);
          // Fall through to fresh resolution (only the cache PROCESSING failed).
        }
        if (cachedOk)
        {
          // Deliver OUTSIDE the try: a throwing USER callback must not be conflated with a
          // cache-processing failure and trigger a wasted fresh resolution (steps-4-8
          // thread-safety L-1). The single-fire gate keeps delivery at-most-once regardless.
          callback(cachedResult, nullptr);
          return;
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
        // (secure is applied inside performServiceResolutionAsync; this logging wrapper
        // does not re-filter.)
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
      preferredTransports, secure);
  }

  /// \brief Perform standard DNS query, with RFC 1035 §7.2 next-server failover.
  ///
  /// A recursive-resolver SERVER-LOCAL failure — an rcode-bearing negative
  /// (SERVFAIL/REFUSED/FORMERR/NOTIMP/NODATA-without-SOA/other error rcode) OR a thrown
  /// transport fault (timeout, connect/send failure, per-server query-ID exhaustion) — is
  /// retried on the NEXT configured server (excluding tried), until a success, an
  /// AUTHORITATIVE negative (NXDOMAIN / NODATA-with-SOA — which STOPS rotation), or all
  /// servers are exhausted. Server selection is OWNED here (never getNextServer()): one
  /// getConfig() snapshot pins the server list, and a resolver-owned rotating cursor picks
  /// the starting server (tracker 2026-09-25-8).
  ///
  /// \param question DNS question to resolve
  /// \return DNS query result
  /// \throws DnsResolutionFailedException / DnsNoRecordsException on an AUTHORITATIVE negative
  /// \throws DnsTransientResolutionException when all servers are exhausted on server-local
  ///         conditions (transient, retryable — preserves the transient signal)
  /// \throws DnsTransportException on a TERMINAL lifecycle fault (transport stopped, etc.)
  DnsResult query(const DnsQuestion &question)
  {
    // Cache check ONCE before the failover loop. A negative cache entry is only ever an
    // AUTHORITATIVE negative (cacheQueryResult never caches a no-SOA negative, RFC 2308 §5),
    // so a negative hit is permanent — throw the authoritative exception, never transient.
    if (_cache)
    {
      DnsResult cached;
      if (_cache->get(question, cached))
      {
        if (!cached.isSuccess())
        {
          throw DnsResolutionFailedException(question.qname, cached.header.rcode);
        }
        return cached;
      }
    }

    // Pin ONE server-list snapshot for this failover chain (INV-2): size, cursor, and each
    // element are read from the same immutable vector a concurrent updateConfig() cannot tear.
    auto cfg = _transport->getConfig();
    if (!cfg || cfg->servers.empty())
    {
      throw DnsTransportException("No DNS servers configured");
    }
    const std::size_t serverCount = cfg->servers.size();
    const std::size_t start =
      _serverRotation.fetch_add(1, std::memory_order_relaxed) % serverCount;

    // Remember the last server-local outcome (rcode result or thrown fault) so the terminal
    // transient throw after exhaustion is faithful to what the last server reported.
    DnsResponseCode lastServerLocalRcode = DnsResponseCode::SERVFAIL;

    for (std::size_t i = 0; i < serverCount; ++i)
    {
      // Explicit per-server iteration excluding tried — never getNextServer() (a blind shared
      // round-robin with no failover memory). Each server is contacted at most once.
      const DnsServer &srv = cfg->servers[(start + i) % serverCount];
      try
      {
        DnsResult result = _transport->query(question, srv.address, srv.port);

        if (result.isSuccess())
        {
          cacheQueryResult(question, result); // terminal (positive) — cache once
          return result;
        }

        // Non-success rcode-bearing negative: classify by the detection gate.
        if (isAuthoritativeNegative(result))
        {
          // NXDOMAIN / NODATA-with-SOA -> permanent. STOP rotation; cache the authoritative
          // negative (RFC 2308) and throw the authoritative exception.
          cacheQueryResult(question, result);
          throw DnsResolutionFailedException(question.qname, result.header.rcode);
        }

        // Q5 (human decision 2026-09-30): a NAPTR query answered NOTIMP/FORMERR means the
        // server does not implement NAPTR — the other configured servers are likely the same
        // infrastructure, so do NOT rotate all servers. Fall STRAIGHT to direct-SRV: throw a
        // DnsResolverException-derived type after this single NAPTR query so the NAPTR path's
        // step-fallback catch triggers direct-SRV. (NAPTR still rotates on SERVFAIL/REFUSED/
        // timeout — those are transient server-local faults, not "NAPTR unsupported".)
        if (question.qtype == DnsType::NAPTR &&
            (result.header.rcode == DnsResponseCode::NOTIMP ||
             result.header.rcode == DnsResponseCode::FORMERR))
        {
          throw DnsTransientResolutionException(question.qname, result.header.rcode);
        }

        // SERVFAIL / REFUSED / FORMERR / NOTIMP / other error rcode / NODATA-without-SOA ->
        // SERVER-LOCAL: rotate to the next server. Never cached (no SOA / not authoritative).
        lastServerLocalRcode = result.header.rcode;
        // fall through to next iteration
      }
      catch (const DnsTimeoutException &)
      {
        lastServerLocalRcode = DnsResponseCode::SERVFAIL; // server-local -> rotate
      }
      catch (const DnsNetworkException &)
      {
        lastServerLocalRcode = DnsResponseCode::SERVFAIL; // server-local -> rotate
      }
      catch (const DnsTransportException &)
      {
        // TERMINAL lifecycle fault (Transport not running / stopped / No questions provided /
        // DNS session closed): not server-local — no rotation, propagate as-is.
        throw;
      }
      // std::bad_alloc and any other exception propagate (terminal).
    }

    // All servers exhausted on server-local conditions -> TRANSIENT (retryable). Preserve the
    // transient signal as a distinct type so resolveHostname / callers can map it to a 503
    // rather than a permanent no-service (RFC 3263). Never cached.
    throw DnsTransientResolutionException(question.qname, lastServerLocalRcode);
  }

  /// \brief Detection gate: is a non-success DnsResult an AUTHORITATIVE negative
  ///        (NXDOMAIN / NODATA-with-SOA) that must STOP next-server rotation, versus a
  ///        SERVER-LOCAL negative (SERVFAIL/REFUSED/FORMERR/NOTIMP/other error rcode /
  ///        NODATA-without-SOA) that must rotate? (tracker 2026-09-25-8).
  /// \pre result.isSuccess() == false (a rcode-bearing negative response).
  static bool isAuthoritativeNegative(const DnsResult &result)
  {
    const DnsResponseCode rc = result.header.rcode;
    if (rc == DnsResponseCode::NXDOMAIN)
    {
      return true; // the name authoritatively does not exist
    }
    if (rc == DnsResponseCode::NOERROR)
    {
      // NODATA (NOERROR + no answers): authoritative iff it carries an SOA (RFC 2308 §5).
      return negativeResponseHasSoa(result);
    }
    // SERVFAIL, REFUSED, FORMERR, NOTIMP, and any other error rcode are server-local.
    return false;
  }

  /// \brief Per-failover-chain state for one INDEPENDENT async transport issue (tracker
  ///        2026-09-25-8). A and AAAA are separate issues, so the failover unit is the
  ///        per-family issue, NOT the target slot — each gets its own chain.
  ///
  /// Heap-allocated (make_shared) and captured BY VALUE into every helper/re-issue lambda,
  /// alongside self = shared_from_this(). Re-issues within one chain are SERIAL (the transport's
  /// register->complete edge under _queriesMutex gives happens-before), so the trampoline flags
  /// and `tried` need no atomics — but they MUST live here (heap), never as stack locals.
  struct FailoverChainState
  {
    std::shared_ptr<const DnsConfig> snapshot; ///< pinned server list (one snapshot per chain)
    std::vector<char> tried;                   ///< per-server-index "already attempted" flag
    std::size_t startIndex{0};                  ///< rotating start server (load spread)
    std::size_t attempts{0};                    ///< bounded by server count (finiteness)
    // Trampoline flags: distinguish a SYNCHRONOUS completion (callback fired inside the
    // queryAsync issue call) from an ASYNC one, so a synchronously-completing transport
    // advances via the issue LOOP (iterative) rather than deep self-recursion (ts-LOW-2).
    bool issuing{false};                        ///< true while inside a queryAsync issue call
    bool advance{false};                        ///< set by a synchronous server-local completion
  };

  /// \brief Build a fresh failover chain: pin one getConfig() snapshot and pick a rotating
  ///        starting server from the resolver-owned cursor. An empty/absent snapshot yields a
  ///        chain whose first pick fails -> the helper funnels a terminal transient (never a
  ///        silent empty).
  std::shared_ptr<FailoverChainState> makeFailoverChain()
  {
    auto chain = std::make_shared<FailoverChainState>();
    chain->snapshot = _transport->getConfig();
    const std::size_t n = (chain->snapshot ? chain->snapshot->servers.size() : 0);
    chain->tried.assign(n, 0);
    chain->startIndex =
      (n > 0 ? (_serverRotation.fetch_add(1, std::memory_order_relaxed) % n) : 0);
    return chain;
  }

  /// \brief Async detection gate: does an async completion (result,error) mean "rotate to the
  ///        next server" (server-local) or "deliver terminal"? Mirrors the sync gate.
  enum class AsyncFailoverVerdict
  {
    Terminal,        ///< success / authoritative-negative / lifecycle fault / Q5 -> deliver as-is
    ServerLocalRetry ///< SERVFAIL/REFUSED/FORMERR/NOTIMP/NODATA-no-SOA/timeout/network -> rotate
  };
  static AsyncFailoverVerdict classifyAsyncCompletion(const DnsQuestion &question,
                                                      const DnsResult &result,
                                                      const std::exception_ptr &error)
  {
    if (error)
    {
      try
      {
        std::rethrow_exception(error);
      }
      catch (const DnsTimeoutException &)
      {
        return AsyncFailoverVerdict::ServerLocalRetry;
      }
      catch (const DnsNetworkException &)
      {
        return AsyncFailoverVerdict::ServerLocalRetry;
      }
      catch (...)
      {
        // Lifecycle DnsTransportException (not running/stopped/no questions), std::bad_alloc,
        // and anything else are TERMINAL — no rotation.
        return AsyncFailoverVerdict::Terminal;
      }
    }
    // A delivered result (no error).
    if (result.isSuccess() || isAuthoritativeNegative(result))
    {
      return AsyncFailoverVerdict::Terminal;
    }
    // Q5: a NAPTR answered NOTIMP/FORMERR means "NAPTR unsupported" — deliver as-is so the NAPTR
    // completer falls straight to direct-SRV, WITHOUT rotating all servers (they are likely the
    // same infra). NAPTR still rotates on SERVFAIL/REFUSED/timeout (below).
    if (question.qtype == DnsType::NAPTR &&
        (result.header.rcode == DnsResponseCode::NOTIMP ||
         result.header.rcode == DnsResponseCode::FORMERR))
    {
      return AsyncFailoverVerdict::Terminal;
    }
    // SERVFAIL / REFUSED / FORMERR / other error rcode / NODATA-without-SOA -> rotate.
    return AsyncFailoverVerdict::ServerLocalRetry;
  }

  /// \brief True iff \p error is a DnsTransientResolutionException (all-server exhaustion on
  ///        server-local conditions) — the async twin of the sync transient signal. Used at the
  ///        terminal delivery points to set ServiceResolutionResult::outcome (tracker 2026-09-25-8).
  static bool isTransientError(const std::exception_ptr &error)
  {
    if (!error)
    {
      return false;
    }
    try
    {
      std::rethrow_exception(error);
    }
    catch (const DnsTransientResolutionException &)
    {
      return true;
    }
    catch (...)
    {
      return false;
    }
  }

  /// \brief Async next-server failover (RFC 1035 §7.2): the drop-in replacement for a direct
  ///        _transport->queryAsync(question, wrappedCallback) at every resolver async issue site.
  ///
  /// Issues \p question to the next non-excluded server in \p chain. In its own callback it
  /// classifies the completion (classifyAsyncCompletion): a SERVER-LOCAL result with servers
  /// remaining re-issues to the next server (does NOT invoke \p wrappedCallback, does NOT touch
  /// any latch); every TERMINAL outcome invokes \p wrappedCallback EXACTLY ONCE. On server
  /// exhaustion (or an empty snapshot) it invokes \p wrappedCallback once with a transient error.
  ///
  /// CONTRACT (load-bearing for the no-backstop A/AAAA finishTarget latch): this helper NEVER
  /// propagates a throw to its caller — every issue (first + re-issue) is wrapped, and a
  /// synchronous issue-throw becomes either a next-server advance (network throw) or exactly ONE
  /// terminal \p wrappedCallback (any other throw). So a site-level catch around the helper call
  /// is reachable only for PRE-CALL throws. The next-server advance is ITERATIVE (a synchronous
  /// completion loops here) — never deep self-recursion (ts-LOW-2). \p wrappedCallback runs with
  /// no resolver lock held (the caller must not hold *resultMutex across this — AP-1).
  void queryAsyncWithFailover(const DnsQuestion &question,
                              const std::shared_ptr<FailoverChainState> &chain,
                              QueryCallback wrappedCallback)
  {
    auto self = shared_from_this();
    while (true)
    {
      // Pick the next non-tried server from the pinned snapshot.
      const std::size_t n = (chain->snapshot ? chain->snapshot->servers.size() : 0);
      std::size_t pick = n; // sentinel = "none left"
      for (std::size_t i = 0; i < n; ++i)
      {
        const std::size_t idx = (chain->startIndex + i) % n;
        if (!chain->tried[idx])
        {
          pick = idx;
          break;
        }
      }
      if (pick == n)
      {
        // Empty snapshot OR all servers exhausted on server-local conditions -> terminal
        // transient (retryable), delivered EXACTLY ONCE. Never a silent empty (ts-LOW-1).
        wrappedCallback(DnsResult{},
                        std::make_exception_ptr(DnsTransientResolutionException(question.qname)));
        return;
      }
      chain->tried[pick] = 1;
      ++chain->attempts;
      const DnsServer server = chain->snapshot->servers[pick]; // value copy

      chain->issuing = true;
      chain->advance = false;
      try
      {
        // The transport mints a fresh unique query id per issue (generateUniqueQueryId), so each
        // re-issue is a distinct in-flight query the transport dedups exactly-once. Pass the
        // explicit server+port so failover actually targets a DIFFERENT server.
        _transport->queryAsync(
          question,
          [self, chain, question, wrappedCallback](const DnsResult &result,
                                                   const std::exception_ptr &error)
          {
            if (classifyAsyncCompletion(question, result, error) ==
                AsyncFailoverVerdict::ServerLocalRetry)
            {
              if (chain->issuing)
              {
                // Synchronous completion (inline, same stack as the issue call): signal the
                // issue LOOP to advance to the next server (iterative, no deep recursion).
                chain->advance = true;
              }
              else
              {
                // Asynchronous completion (worker thread, stack already unwound): re-enter the
                // helper directly to issue to the next server.
                self->queryAsyncWithFailover(question, chain, wrappedCallback);
              }
            }
            else
            {
              // Terminal: success / authoritative-negative / lifecycle fault / Q5. Deliver
              // exactly once. The completer runs with no resolver lock held (HR-3).
              wrappedCallback(result, error);
            }
          },
          server.address, server.port);
      }
      catch (const DnsTimeoutException &)
      {
        chain->issuing = false;
        continue; // synchronous server-local issue-throw -> advance to next server
      }
      catch (const DnsNetworkException &)
      {
        chain->issuing = false;
        continue; // synchronous per-server network issue-throw -> advance
      }
      catch (...)
      {
        // Any other synchronous issue-throw (lifecycle DnsTransportException, std::bad_alloc, a
        // test double's injected throw) is TERMINAL -> exactly ONE wrappedCallback. NEVER
        // rethrow (the no-backstop finishTarget latch depends on fire-XOR-nothing here).
        chain->issuing = false;
        wrappedCallback(DnsResult{}, std::current_exception());
        return;
      }
      chain->issuing = false;
      if (chain->advance)
      {
        continue; // a synchronous server-local completion asked to advance -> next server
      }
      return; // async issue in flight (callback will re-enter), or a terminal already fired
    }
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

    // Perform async query WITH next-server failover (tracker 2026-09-25-8). The helper never
    // propagates a throw, so this try only guards the PRE-CALL statements (makeFailoverChain /
    // shared_from_this); a synchronous issue-throw is funneled into the callback by the helper.
    auto self = shared_from_this();
    try
    {
      auto chain = makeFailoverChain();
      queryAsyncWithFailover(
        question, chain,
        [self, question, callback](const DnsResult &result, const std::exception_ptr &ex)
        {
          if (ex)
          {
            // Includes DnsTransientResolutionException on all-server exhaustion (parity with
            // the sync query() transient signal).
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
    catch (...)
    {
      callback(DnsResult{}, std::current_exception());
    }
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

    // Per-avenue transient tracking (tracker 2026-09-25-8): resolveHostname signals failure
    // by THROWING. A per-family SERVER-LOCAL exhaustion surfaces from query() as a
    // DnsTransientResolutionException; if the combined result is empty, the terminal must
    // preserve that transient (retryable) signal rather than flattening every failure to a
    // permanent DnsNoRecordsException(NXDOMAIN). We keep DnsNoRecordsException only for the
    // all-authoritative-negative case.
    bool anyTransient = false;

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
      catch (const DnsTransientResolutionException &)
      {
        // A-family server-local exhaustion (all servers SERVFAIL/timeout/etc.) -> TRANSIENT.
        // Continue to AAAA (a sibling family may still succeed — a partial success is NOT
        // overridden by a transient sibling), but remember the transient for the terminal.
        anyTransient = true;
      }
      catch (const DnsResolverException &)
      {
        // IPv4 query hit an AUTHORITATIVE negative (NXDOMAIN / NODATA-with-SOA), continue.
      }
      catch (const DnsTransportException &)
      {
        // A TERMINAL lifecycle fault (transport stopped, etc.). Per-family timeouts no longer
        // reach here (query() rotates and converts them to the transient exception above);
        // keep any partial results and continue to AAAA.
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
      catch (const DnsTransientResolutionException &)
      {
        // AAAA-family server-local exhaustion -> TRANSIENT. DO NOT discard A results already
        // collected; remember the transient for the terminal.
        anyTransient = true;
      }
      catch (const DnsResolverException &)
      {
        // IPv6 query hit an AUTHORITATIVE negative, continue.
      }
      catch (const DnsTransportException &)
      {
        // TERMINAL lifecycle fault: DO NOT discard the A results already collected. This is
        // the dual-stack SIP target case (finding #1) — combine returns the IPv4 addresses
        // instead of throwing out of resolveHostname.
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

    // No addresses from either family -> preserve the transient-vs-permanent distinction
    // (tracker 2026-09-25-8). If ANY queried family exhausted all servers on server-local
    // conditions (transient), throw the transient-preserving type so a caller maps it to a
    // 503 (retryable) rather than a permanent no-service. Only when every queried family ended
    // in an AUTHORITATIVE negative do we throw DnsNoRecordsException (RFC 3263 §4.2 no-record).
    // (A former outer try/catch here re-threw an identically-constructed DnsNoRecordsException;
    // removed as a provable no-op now that the inner A/AAAA catches absorb transport/parse
    // errors — slice a1 review L-h.)
    if (addresses.empty())
    {
      if (anyTransient)
      {
        throw DnsTransientResolutionException(hostname);
      }
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
  /// \param secure RFC 3263 §4.1 SIPS SIP-scoped secure resolution (custom set filtered to
  ///        secure SIP services; non-SIPS-SIP discarded); NOT generic transport security.
  /// \return Service resolution result
  ServiceResolutionResult performDirectSrvResolution(
    const std::string &domain, const std::vector<ServiceType> &preferredTransports,
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries =
      std::nullopt,
    bool secure = false)
  {
    ServiceResolutionResult result(domain);

    auto actualSrvQueries = buildOrderedSrvQueries(domain, srvQueries, preferredTransports, secure);

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
      sortTargetsByPriority(result, secure);
    }
    else
    {
      // No SRV targets: fall back to A/AAAA on the domain for the transports that
      // were NOT explicitly declared unavailable by an SRV "." (RFC 2782).
      performFallbackResolution(domain, result, preferredTransports, deniedServices, secure);
    }

    return result;
  }

  /// \brief Perform direct SRV resolution asynchronously (generic version)
  /// \param domain Domain to resolve
  /// \param callback Result callback
  /// \param preferredTransports Preferred transport types
  /// \param srvQueries Custom SRV queries to perform (defaults to SIP services for backward
  /// compatibility)
  /// \param secure RFC 3263 §4.1 SIPS SIP-scoped secure resolution (custom set filtered to
  ///        secure SIP services; non-SIPS-SIP discarded); NOT generic transport security.
  void performDirectSrvResolutionAsync(
    const std::string &domain, ServiceResolutionCallback callback,
    const std::vector<ServiceType> &preferredTransports,
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries =
      std::nullopt,
    bool secure = false)
  {
    // Deliver AT MOST ONCE (this is a public entry; double-wrapping when reached via
    // performServiceResolutionAsync is harmless) -- tracker 2026-09-25-5 steps-4-8 H-1.
    callback = makeSingleFire(std::move(callback));

    auto actualSrvQueries = buildOrderedSrvQueries(domain, srvQueries, preferredTransports, secure);

    auto result = std::make_shared<ServiceResolutionResult>(domain);

    // Zero-work guard: with no SRV queries to issue, the per-query completion block
    // below never runs, so the user callback would never fire (caller hangs). Mirror
    // the sync path and fall back directly.
    if (actualSrvQueries.empty())
    {
      performFallbackResolutionAsync(domain, result, callback, preferredTransports, {}, secure);
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

    auto self = shared_from_this();

    // Shared completer: the last query to decrement to zero runs the join. acq_rel
    // publishes every prior callback's locked writes (targets/deniedServices) to this
    // thread. Invoked from each SRV callback AND from a synchronous issue-throw catch
    // (TS-C1); callbackFired makes it single-fire regardless. The continuation is
    // wrapped so a prelude throw (e.g. bad_alloc) delivers via the callback instead of
    // unwinding into the DNS worker (tracker 2026-09-25-5 TS-M2).
    auto runCompleter = std::make_shared<std::function<void()>>(
      [self, result, remainingQueries, callbackFired, callback, domain, preferredTransports,
       deniedServices, secure]()
      {
        if (remainingQueries->fetch_sub(1, std::memory_order_acq_rel) == 1 &&
            !callbackFired->exchange(true))
        {
          try
          {
            if (!result->targets.empty())
            {
              self->resolveTargetAddressesAsync(result, callback, secure);
            }
            else
            {
              // No SRV targets: fall back to A/AAAA for the transports NOT declared
              // unavailable by an SRV "." (RFC 2782). If every fallback transport is
              // denied, performFallbackResolutionAsync yields an empty result and
              // still fires the callback exactly once.
              self->performFallbackResolutionAsync(domain, result, callback, preferredTransports,
                                                   *deniedServices, secure);
            }
          }
          catch (...)
          {
            callback(*result, std::current_exception());
          }
        }
      });

    // The query's index in the preference-ordered actualSrvQueries is the per-set transport
    // rank; snapshot it per-iteration and capture BY VALUE so each completion lambda stamps its
    // own set's rank (2026-09-25-4 fix A — mirrors the NAPTR-async by-value idiom).
    for (std::size_t rank = 0; rank < actualSrvQueries.size(); ++rank)
    {
      try
      {
        // Pre-issue statements inside the try (the helper is no-throw; this catch guards only
        // these PRE-CALL statements + makeFailoverChain, tracker 2026-09-25-8).
        const auto &srvName = actualSrvQueries[rank].first;
        const auto service = actualSrvQueries[rank].second;
        const auto transportRank = static_cast<std::uint16_t>(rank);
        DnsQuestion srvQuestion(srvName, DnsType::SRV, DnsClass::IN);
        auto chain = makeFailoverChain();

        queryAsyncWithFailover(
          srvQuestion, chain,
          [self, result, service, transportRank, resultMutex, deniedServices, runCompleter](
            const DnsResult &srvResult, const std::exception_ptr &srvError)
          {
            // srvError set (incl. DnsTransientResolutionException on all-server exhaustion) ->
            // this SRV set contributed nothing; the fan-out continues with the other sets.
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
            (*runCompleter)();
          });
      }
      catch (...)
      {
        (*runCompleter)(); // TS-C1: synchronous issue throw -> decrement once + complete-if-last
      }
    }
  }

private:
  std::shared_ptr<DnsTransport> _transport; ///< DNS transport layer
  std::shared_ptr<DnsCache> _cache;         ///< DNS cache (optional)
  // const: set once at construction, read lock-free from concurrent worker/caller
  // callbacks (addressResolutionPolicy). Compiler-enforced immutability is the basis
  // of the lock-free read (tracker 2026-09-25-5 ts-L1). DnsResolver is already
  // non-copyable/non-movable via _rngMutex, so const adds no assignability constraint.
  const DnsConfig _config;                  ///< DNS configuration (immutable after ctor)

  /// \brief Centralized random number generator for deterministic testing
  mutable std::mt19937 _rng;    ///< Weighted SRV selection RNG (guarded by _rngMutex)
  mutable std::mutex _rngMutex; ///< Guards _rng against concurrent advance/seed

  /// \brief Resolver-owned round-robin cursor for next-server failover (tracker 2026-09-25-8).
  /// The resolver OWNS server selection during failover; the transport's own _serverIndex is
  /// private and rotates per-distinct-query with no failover memory. A relaxed fetch_add gives
  /// each new failover chain a fresh starting server (load spread) while the loop then iterates
  /// the remainder explicitly, excluding tried servers — so getNextServer() is never called in
  /// the loop.
  mutable std::atomic<std::size_t> _serverRotation{0};

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
  /// \param secure RFC 3263 §4.1 SIPS SIP-scoped secure resolution; NOT generic transport
  ///        security.
  /// \return Service resolution result
  ServiceResolutionResult
  performServiceResolution(const std::string &domain,
                           const std::vector<ServiceType> &preferredTransports, bool secure = false)
  {
    ServiceResolutionResult result(domain);

    // Every NAPTR-failure and no-usable-NAPTR path converges on the same RFC 3263
    // §4.1 direct-SRV fallback, so name it once (review L-f).
    auto fallbackToDirectSrv = [&]()
    { return performDirectSrvResolution(domain, preferredTransports, std::nullopt, secure); };

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
    processNaptrRecords(naptrRecords, srvTargets, aTargets, preferredTransports, secure);

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

    // Step 5: Sort targets by priority (and, when secure, discard any non-SIPS-SIP
    // target as belt-and-suspenders — the primary NAPTR/SRV filters already excluded them).
    sortTargetsByPriority(result, secure);

    return result;
  }

  /// \brief Perform SIP resolution asynchronously
  /// \param domain Domain to resolve
  /// \param callback Result callback
  /// \param preferredTransports Preferred transport types
  void performServiceResolutionAsync(const std::string &domain, ServiceResolutionCallback callback,
                                     const std::vector<ServiceType> &preferredTransports,
                                     bool secure = false)
  {
    auto self = shared_from_this();

    // Entry-site TS-C1: a synchronous issue throw at the initial NAPTR issue delivers via the
    // callback (uniform deliver-via-callback contract). WITH next-server failover (tracker
    // 2026-09-25-8): NAPTR rotates on SERVFAIL/REFUSED/timeout; a NAPTR NOTIMP/FORMERR is
    // delivered as-is (Q5) so the completer falls straight to direct-SRV without rotating.
    try
    {
      DnsQuestion naptrQuestion(domain, DnsType::NAPTR, DnsClass::IN);
      auto chain = makeFailoverChain();
      queryAsyncWithFailover(
        naptrQuestion, chain,
        [self, domain, callback, preferredTransports, secure](const DnsResult &naptrResult,
                                                              const std::exception_ptr &naptrError)
        {
          // TS-M2: a continuation invoked from this worker-thread callback can throw in
          // its prelude (e.g. bad_alloc before its first wrapped queryAsync); deliver via
          // the callback rather than unwinding into the worker. Guards the whole body;
          // the paths below fire the callback and return before reaching the end, so this
          // catch only fires on a prelude throw (no callback yet) — never a double-fire.
          try
          {
            if (naptrError)
            {
              // No NAPTR records, try direct SRV resolution
              self->performDirectSrvResolutionAsync(domain, callback, preferredTransports,
                                                    std::nullopt, secure);
              return;
            }

            // Process NAPTR records to get SRV and direct-A targets
            std::vector<NaptrSrvTarget> srvTargets;
            std::vector<NaptrDirectTarget> aTargets;
            try
            {
              self->processNaptrRecords(naptrResult.naptr_records, srvTargets, aTargets,
                                        preferredTransports, secure);
            }
            catch (const std::exception &e)
            {
              callback(ServiceResolutionResult(domain), std::make_exception_ptr(e));
              return;
            }

            if (srvTargets.empty() && aTargets.empty())
            {
              // No valid targets, try direct SRV resolution
              self->performDirectSrvResolutionAsync(domain, callback, preferredTransports,
                                                    std::nullopt, secure);
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
              self->resolveTargetAddressesAsync(result, callback, secure);
              return;
            }

            auto remainingQueries = std::make_shared<std::atomic<size_t>>(srvTargets.size());
            // callbackFired ensures the completion callback is invoked exactly once
            auto callbackFired = std::make_shared<std::atomic<bool>>(false);
            // Mutex protects concurrent writes to result->targets from parallel SRV callbacks
            auto resultMutex = std::make_shared<std::mutex>();

            // Shared completer: last SRV query runs the join; the TS-C1 issue-throw catch
            // reuses it (callbackFired keeps it single-fire); the continuation is wrapped
            // so a prelude throw delivers via the callback, not into the worker (TS-M2).
            auto runCompleter = std::make_shared<std::function<void()>>(
              [self, result, remainingQueries, callbackFired, callback, secure]()
              {
                if (remainingQueries->fetch_sub(1, std::memory_order_acq_rel) == 1 &&
                    !callbackFired->exchange(true))
                {
                  try
                  {
                    self->resolveTargetAddressesAsync(result, callback, secure);
                  }
                  catch (...)
                  {
                    callback(*result, std::current_exception());
                  }
                }
              });

            for (const auto &srvTarget : srvTargets)
            {
              try
              {
                // Pre-issue statements inside the try (the helper is no-throw; this catch guards
                // only these PRE-CALL statements + makeFailoverChain, tracker 2026-09-25-8).
                DnsQuestion srvQuestion(srvTarget.srvName, DnsType::SRV, DnsClass::IN);
                auto service = srvTarget.service;
                auto naptrPref = srvTarget.naptrPreference;
                auto chain = self->makeFailoverChain();

                self->queryAsyncWithFailover(
                  srvQuestion, chain,
                  [self, result, service, naptrPref, resultMutex, runCompleter](
                    const DnsResult &srvResult, const std::exception_ptr &srvError)
                  {
                    // srvError set (incl. transient exhaustion) -> this SRV set contributed
                    // nothing; the fan-out continues with the other sets.
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
                    (*runCompleter)();
                  });
              }
              catch (...)
              {
                (*runCompleter)(); // TS-C1: synchronous SRV issue throw -> decrement once + complete-if-last
              }
            }
          }
          catch (...)
          {
            // TS-M2: a continuation prelude throw (e.g. bad_alloc in the setup of
            // performDirectSrvResolutionAsync / resolveTargetAddressesAsync) must not
            // unwind into the worker; deliver via the callback exactly once.
            callback(ServiceResolutionResult(domain), std::current_exception());
          }
        });
    }
    catch (...)
    {
      // Entry-site TS-C1: a synchronous NAPTR issue throw delivers via the callback.
      callback(ServiceResolutionResult(domain), std::current_exception());
    }
  }

  /// \brief Process cached SIP resolution from NAPTR result
  /// \param result Result to populate
  /// \param naptrResult Cached NAPTR result
  /// \param preferredTransports Preferred transport types
  void processCachedServiceResolution(ServiceResolutionResult &result, const DnsResult &naptrResult,
                                      const std::vector<ServiceType> &preferredTransports,
                                      bool secure = false)
  {
    // Step 1: Process NAPTR records to get SRV and direct-A targets
    std::vector<NaptrSrvTarget> srvTargets;
    std::vector<NaptrDirectTarget> aTargets;
    processNaptrRecords(naptrResult.naptr_records, srvTargets, aTargets, preferredTransports, secure);

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

    // Step 3: Resolve hostnames from cache, honoring addressResolutionPolicy
    // (family selection + order identical to the sync resolveHostname). Fully
    // synchronous cache reads -- no latch, no mutex (tracker 2026-09-25-5 site 3).
    // For the "First" policies BOTH families are read (not AAAA-only-if-A-empty).
    const std::vector<DnsType> families = familiesInOrder(_config.addressResolutionPolicy);
    for (auto &target : result.targets)
    {
      if (!_cache)
      {
        continue;
      }

      for (DnsType family : families)
      {
        DnsQuestion q(target.hostname, family, DnsClass::IN);
        DnsResult cached;
        if (_cache->get(q, cached))
        {
          appendFamilyAddresses(target.addresses, cached, family);
        }
      }
    }

    // Step 4: Remove targets with no resolved addresses
    result.targets.erase(std::remove_if(result.targets.begin(), result.targets.end(),
                                        [](const ServiceTarget &target)
                                        { return target.addresses.empty(); }),
                         result.targets.end());

    // Step 5: Sort targets by priority (secure belt-discard as defense-in-depth)
    sortTargetsByPriority(result, secure);
  }

  /// \brief Process NAPTR records to extract SRV and direct-A targets
  /// \param naptrRecords NAPTR records to process
  /// \param srvTargets Output: 'S' flag records (replacement is SRV domain name)
  /// \param aTargets Output: 'A' flag records (replacement is hostname for direct A/AAAA)
  /// \param preferredTransports Preferred transport types
  void processNaptrRecords(const std::vector<NaptrRecord> &naptrRecords,
                           std::vector<NaptrSrvTarget> &srvTargets,
                           std::vector<NaptrDirectTarget> &aTargets,
                           const std::vector<ServiceType> &preferredTransports,
                           bool secure = false)
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

      const bool inPreferred =
        preferredTransports.empty() ||
        std::find(preferredTransports.begin(), preferredTransports.end(), service) !=
          preferredTransports.end();
      if (secure)
      {
        // RFC 3263 §4.1: a client resolving a SIPS URI MUST discard any service whose
        // protocol is not SIPS (SIP-scoped — HTTPS+D2T and any non-SIP service are
        // dropped), AND discard SIPS+D2X for a transport X the client does not support.
        // This discard is UNCONDITIONAL (not gated on preferredTransports being non-empty).
        if (!isSecureSipService(service) || !inPreferred)
        {
          continue;
        }
      }
      else if (!inPreferred)
      {
        // Plain sip: supported-set model — discard published transports the client
        // does not support (preferredTransports is the client's supported set).
        continue; // Skip non-supported transports
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
  /// \brief The client's secure SIP transport set (RFC 3263 §4.1): preferredTransports
  /// filtered to secure SIP services, defaulting to {SIPS_TLS} when the caller named no
  /// secure transport. Shared by the default-set SRV query builder (owner-name mapping)
  /// and the A/AAAA-fallback transport list so the §4.1 secure-default rule lives once.
  std::vector<ServiceType>
  secureSupportedOrDefault(const std::vector<ServiceType> &preferredTransports) const
  {
    std::vector<ServiceType> secure;
    std::copy_if(preferredTransports.begin(), preferredTransports.end(),
                 std::back_inserter(secure), isSecureSipService);
    if (secure.empty())
    {
      secure.push_back(ServiceType::SIPS_TLS);
    }
    return secure;
  }

  /// \brief Map a secure SIP transport to its RFC 3263 SRV owner name.
  /// _sips._tcp originates in RFC 3263 itself; the _sips._sctp / _sips._wss service
  /// values SIPS+D2S / SIPS+D2W are normatively registered by RFC 4168 §8 / RFC 7118
  /// §10.2 (wss default port 443), and their SRV owner names follow RFC 3263's normative
  /// _sips._<proto> construction rule. Never _sips._udp: SIPS+D2U SHOULD NOT exist (§4.1).
  static std::string secureSrvOwnerName(ServiceType transport, const std::string &domain)
  {
    switch (transport)
    {
    case ServiceType::SIPS_SCTP:
      return "_sips._sctp." + domain;
    case ServiceType::SIPS_WSS:
      return "_sips._wss." + domain;
    case ServiceType::SIPS_TLS:
    default:
      return "_sips._tcp." + domain;
    }
  }

  /// \brief Build the SRV query list (custom, or the default SIP service set) and
  /// order it by the caller's preferred transports. Shared by the sync and async
  /// direct-SRV paths so the query set and ordering are defined once.
  std::vector<std::pair<std::string, ServiceType>> buildOrderedSrvQueries(
    const std::string &domain,
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries,
    const std::vector<ServiceType> &preferredTransports, bool secure = false) const
  {
    std::vector<std::pair<std::string, ServiceType>> actualSrvQueries;
    if (srvQueries.has_value())
    {
      actualSrvQueries = srvQueries.value();
      if (secure)
      {
        // Custom set + secure (RFC 3263 §4.1): filter the caller's set to secure SIP
        // services — do NOT silently replace it.
        actualSrvQueries.erase(
          std::remove_if(actualSrvQueries.begin(), actualSrvQueries.end(),
                         [](const std::pair<std::string, ServiceType> &q)
                         { return !isSecureSipService(q.second); }),
          actualSrvQueries.end());
      }
    }
    else if (secure)
    {
      // Default set + secure: build the query set BY MAPPING each supported secure SIP
      // transport to its _sips._<proto> owner name (RFC 3263 §4.1 — never query a
      // plaintext service). Default to SIPS_TLS (_sips._tcp) when the caller named no
      // secure transport. Owner names for sctp/wss are de-facto convention (see
      // secureSrvOwnerName); _sips._udp is never emitted (SIPS+D2U SHOULD NOT exist).
      for (ServiceType t : secureSupportedOrDefault(preferredTransports))
      {
        actualSrvQueries.push_back({secureSrvOwnerName(t, domain), t});
      }
    }
    else
    {
      actualSrvQueries = {{"_sips._tcp." + domain, ServiceType::SIPS_TLS},
                          {"_sip._tcp." + domain, ServiceType::SIP_TCP},
                          {"_sip._udp." + domain, ServiceType::SIP_UDP},
                          {"_sip._sctp." + domain, ServiceType::SIP_SCTP}};
      // Plain sip: supported-set model — discard DEFAULT-set queries whose transport the
      // client does not support (preferredTransports is the supported set, RFC 3263 §4.1).
      // Empty preferredTransports = permissive (backward-compatible no-constraint caller).
      if (!preferredTransports.empty())
      {
        actualSrvQueries.erase(
          std::remove_if(actualSrvQueries.begin(), actualSrvQueries.end(),
                         [&preferredTransports](const std::pair<std::string, ServiceType> &q)
                         {
                           return std::find(preferredTransports.begin(),
                                            preferredTransports.end(),
                                            q.second) == preferredTransports.end();
                         }),
          actualSrvQueries.end());
      }
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
                                              const std::vector<ServiceType> &deniedServices,
                                              bool secure = false) const
  {
    std::vector<ServiceType> transports;
    if (secure)
    {
      // RFC 3263 §4.1: "If no SRV records are found, the client SHOULD use TCP for a
      // SIPS URI." FILTER-then-DEFAULT: keep only the client's secure SIP transports,
      // and default to SIPS_TLS (TLS/5061) when none remain. NEVER a plaintext fallback.
      transports = secureSupportedOrDefault(preferredTransports);
    }
    else
    {
      transports = preferredTransports;
      if (transports.empty())
      {
        transports.push_back(ServiceType::SIP_UDP);
      }
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
  /// \brief Belt-and-suspenders: on a secure resolution, erase any target whose
  /// transport is not a secure SIP service (RFC 3263 §4.1). No-op when not secure.
  /// The primary NAPTR/SRV query filters already exclude these; this guards the
  /// SRV/NAPTR/cache delivery paths that flow through sortTargetsByPriority.
  void discardInsecure(ServiceResolutionResult &result, bool secure) const
  {
    if (!secure)
    {
      return;
    }
    result.targets.erase(std::remove_if(result.targets.begin(), result.targets.end(),
                                        [](const ServiceTarget &t)
                                        { return !isSecureSipService(t.transport); }),
                         result.targets.end());
  }

  void sortTargetsByPriority(ServiceResolutionResult &result, bool secure = false)
  {
    discardInsecure(result, secure);
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
  /// \param secure RFC 3263 §4.1 SIPS secure resolution: fallback yields TLS/5061, never
  ///        plaintext. NOT generic transport security.
  void performFallbackResolution(const std::string &domain, ServiceResolutionResult &result,
                                 const std::vector<ServiceType> &preferredTransports,
                                 const std::vector<ServiceType> &deniedServices = {},
                                 bool secure = false)
  {
    try
    {
      // Transports to build fallback targets for, minus any SRV-"." denied service.
      // When secure, fallbackTransports yields only SIPS transports (TLS/5061 default).
      std::vector<ServiceType> transports =
        fallbackTransports(preferredTransports, deniedServices, secure);
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

  // ===========================================================================
  // Address-family policy helpers (tracker 2026-09-25-5)
  //
  // The async/cached A/AAAA sites honor _config.addressResolutionPolicy with
  // family selection + ordering IDENTICAL to the sync resolveHostname (design (i)):
  // For the "First" policies BOTH families are always queried (never gated on the
  // first being empty — that fallback shortcut discards RFC 3263 sec 4.3 failover
  // candidates); for the "Only" policies exactly one family is queried. The two
  // families are issued STRICTLY SEQUENTIALLY per target/domain (the second from
  // inside the first's callback), which preserves the fan-out completion-latch
  // invariants with zero new synchronization and reproduces the sync concatenation
  // order for free (append order == policy order).
  // ===========================================================================

  /// \brief Address families to query, in policy issue order (design (i)).
  static std::vector<DnsType> familiesInOrder(AddressResolutionPolicy policy)
  {
    switch (policy)
    {
    case AddressResolutionPolicy::IPv4Only:
      return {DnsType::A};
    case AddressResolutionPolicy::IPv6Only:
      return {DnsType::AAAA};
    case AddressResolutionPolicy::IPv6First:
      return {DnsType::AAAA, DnsType::A};
    case AddressResolutionPolicy::IPv4First:
    default:
      return {DnsType::A, DnsType::AAAA};
    }
  }

  /// \brief Append one family's addresses from a DnsResult to \p out (in record order).
  static void appendFamilyAddresses(std::vector<std::string> &out, const DnsResult &r, DnsType family)
  {
    // Only A and AAAA reach here (the policy family lists contain no other types).
    assert(family == DnsType::A || family == DnsType::AAAA);
    if (family == DnsType::A)
    {
      for (const auto &rec : r.a_records)
      {
        out.push_back(rec.address);
      }
    }
    else // DnsType::AAAA
    {
      for (const auto &rec : r.aaaa_records)
      {
        out.push_back(rec.address);
      }
    }
  }

  /// \brief Wrap a ServiceResolutionCallback so it is delivered AT MOST ONCE.
  ///
  /// The async resolution machinery has several delivery points that a THROWING user
  /// callback could otherwise re-enter (a continuation invoked inside a TS-M2 catch
  /// re-delivers on the exception; the transport wraps every leaf callback in catch(...),
  /// so throwing callbacks are a handled condition in this codebase). Routing every
  /// delivery through this single-fire gate makes re-entry idempotent (tracker
  /// 2026-09-25-5 steps-4-8 thread-safety H-1). Applied once at each public async entry;
  /// double-wrapping across nested entries is harmless (each gate fires once).
  static ServiceResolutionCallback makeSingleFire(ServiceResolutionCallback cb)
  {
    auto fired = std::make_shared<std::atomic<bool>>(false);
    return [fired, cb = std::move(cb)](const ServiceResolutionResult &r,
                                       const std::exception_ptr &e)
    {
      if (!fired->exchange(true))
      {
        cb(r, e);
      }
    };
  }

  /// \brief Issue the A/AAAA queries for ONE fan-out target, sequentially in policy
  ///        order, invoking \p finishTarget EXACTLY ONCE when the target is fully
  ///        resolved OR an issue throws synchronously.
  ///
  /// TS-C1 (tracker 2026-09-25-5): DnsTransport::queryAsync can throw synchronously
  /// BEFORE arming its callback (fire-callback XOR synchronous-throw). Each issue is
  /// wrapped so a synchronous throw yields exactly the target's one \p finishTarget
  /// (== "produced no records") and never unwinds into the DNS worker loop. The wrap
  /// begins at the top of the body so a DnsQuestion construction throw is covered too.
  /// Writes only result->targets[targetIndex].addresses (disjoint per target, no lock).
  void issueTargetFamily(const std::shared_ptr<ServiceResolutionResult> &result,
                         std::size_t targetIndex, const std::string &hostname,
                         const std::shared_ptr<std::vector<DnsType>> &families, std::size_t famIdx,
                         const std::shared_ptr<std::function<void()>> &finishTarget)
  {
    // Pre-call statements (shared_from_this + DnsQuestion ctor + makeFailoverChain) are inside
    // the try, so a synchronous PRE-CALL throw yields exactly one finishTarget (TS-C1). The
    // failover helper itself NEVER throws — it converts a synchronous issue-throw into exactly
    // one terminal wrappedCallback (fire-XOR-nothing), which is load-bearing here: this
    // finishTarget latch has NO callbackFired backstop, so a helper that both fired AND rethrew
    // would double-finish this target (tracker 2026-09-25-8).
    try
    {
      auto self = shared_from_this();
      DnsQuestion q(hostname, (*families)[famIdx], DnsClass::IN);
      auto chain = self->makeFailoverChain();
      self->queryAsyncWithFailover(
        q, chain, [self, result, targetIndex, hostname, families, famIdx, finishTarget](
                    const DnsResult &r, const std::exception_ptr &err)
        {
          // Guard the append so a throwing push_back (bad_alloc) still reaches the
          // chain/decrement below -- otherwise the throw is swallowed by the transport's
          // leaf catch(...) and this target's finishTarget never runs -> latch-loss hang
          // (the TS-C1 issue-path guard does not cover the callback body). Steps-4-8 M1.
          try
          {
            if (!err && targetIndex < result->targets.size())
            {
              appendFamilyAddresses(result->targets[targetIndex].addresses, r, (*families)[famIdx]);
            }
          }
          catch (...)
          {
            // Partial addresses (if any) are kept; proceed so the decrement always runs.
          }
          if (famIdx + 1 < families->size())
          {
            // Chain the next family (sequential per target). issueTargetFamily is
            // itself TS-C1-guarded, so a synchronous throw there cannot escape.
            self->issueTargetFamily(result, targetIndex, hostname, families, famIdx + 1, finishTarget);
          }
          else
          {
            (*finishTarget)(); // terminal leaf: exactly-one decrement (acq_rel) + completer-if-last
          }
        });
    }
    catch (...)
    {
      (*finishTarget)(); // TS-C1: synchronous issue throw -> finish this target exactly once
    }
  }

  /// \brief Issue the A/AAAA queries for the single-domain fallback chain,
  ///        sequentially in policy order, invoking \p finish EXACTLY ONCE.
  ///
  /// Single domain, no fan-out latch: \p finish appends the fallback targets with the
  /// collected (policy-ordered) addresses and fires the user callback exactly once.
  /// TS-C1: a synchronous issue throw still fires \p finish once (no caller/worker unwind).
  void issueFallbackFamily(const std::string &domain,
                           const std::shared_ptr<std::vector<DnsType>> &families, std::size_t famIdx,
                           const std::shared_ptr<std::vector<std::string>> &addresses,
                           const std::shared_ptr<std::function<void()>> &finish,
                           const std::shared_ptr<bool> &anyTransient)
  {
    // Pre-call statements inside the try so a synchronous PRE-CALL throw yields exactly one
    // finish (TS-C1); the failover helper is no-throw and funnels a synchronous issue-throw into
    // its callback (tracker 2026-09-25-8). This is a single serial chain (one family at a time),
    // so *anyTransient is written without a data race.
    try
    {
      auto self = shared_from_this();
      DnsQuestion q(domain, (*families)[famIdx], DnsClass::IN);
      auto chain = self->makeFailoverChain();
      self->queryAsyncWithFailover(
        q, chain,
        [self, domain, families, famIdx, addresses, finish, anyTransient](
          const DnsResult &r, const std::exception_ptr &err)
        {
          // Guard the append (bad_alloc) so the chain/finish below always runs -- else the
          // throw is swallowed by the transport leaf catch(...) and the user callback never
          // fires (no latch here, but the same lost-completion class). Steps-4-8 M1.
          try
          {
            if (!err)
            {
              appendFamilyAddresses(*addresses, r, (*families)[famIdx]);
            }
            else if (isTransientError(err))
            {
              // This family exhausted all servers on server-local conditions -> the fallback
              // avenue is (at least partly) transient; the finish below uses it to set outcome.
              *anyTransient = true;
            }
          }
          catch (...)
          {
          }
          if (famIdx + 1 < families->size())
          {
            self->issueFallbackFamily(domain, families, famIdx + 1, addresses, finish, anyTransient);
          }
          else
          {
            (*finish)();
          }
        });
    }
    catch (...)
    {
      (*finish)();
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
                                      const std::vector<ServiceType> &deniedServices = {},
                                      bool secure = false)
  {
    // Transports to build fallback targets for, minus any SRV-"." denied service.
    // When secure, fallbackTransports yields only SIPS transports (TLS/5061 default),
    // so appendFallbackTargets below never produces a plaintext target — no belt needed.
    // If none remain, there is nothing to resolve — fire the callback immediately.
    auto transportsToUse = fallbackTransports(preferredTransports, deniedServices, secure);
    if (transportsToUse.empty())
    {
      callback(*result, nullptr);
      return;
    }

    // Honor addressResolutionPolicy: query the policy's families sequentially (both
    // for the "First" policies -- not AAAA-only-if-A-empty, which would drop the
    // dual-stack failover set), collecting addresses in policy order, then append the
    // fallback targets and fire the callback EXACTLY ONCE (tracker 2026-09-25-5 site 2).
    // Single-domain chain: no fan-out latch.
    auto self = shared_from_this();
    auto families =
      std::make_shared<std::vector<DnsType>>(familiesInOrder(_config.addressResolutionPolicy));
    auto addresses = std::make_shared<std::vector<std::string>>();

    // finish: append fallback targets with the collected addresses and fire the callback.
    // Single-fire (fired-guard): invoked from the last family's callback OR from a
    // synchronous issue-throw catch (TS-C1), and a throwing callback must not re-enter it
    // (steps-4-8 H-1) -- so appendFallbackTargets and the delivery each run at most once.
    // Empty-guard: when nothing resolves under the policy, emit NO target (mirror the sync
    // resolveHostname DnsNoRecords semantics; never a fallback target with empty addresses
    // that would make isSuccess() falsely true) -- steps-4-8 sip-voip H-1.
    auto fired = std::make_shared<std::atomic<bool>>(false);
    // Per-avenue transient signal for this fallback avenue (tracker 2026-09-25-8): set true when a
    // family exhausts all servers on server-local conditions. Written serially in the single
    // fallback chain, read once in finish. When the fallback yields no addresses, it distinguishes
    // a TRANSIENT no-service (retryable) from a PERMANENT one, so the delivered result carries the
    // terminal avenue's per-avenue outcome (the cross-step refinement is tracker 2026-09-30-1).
    auto anyTransient = std::make_shared<bool>(false);
    auto finish = std::make_shared<std::function<void()>>(
      [self, result, domain, transportsToUse, addresses, callback, fired, anyTransient]()
      {
        if (fired->exchange(true))
        {
          return;
        }
        if (!addresses->empty())
        {
          self->appendFallbackTargets(*result, domain, transportsToUse, *addresses);
          result->outcome = ResolutionOutcome::Resolved;
        }
        else
        {
          result->outcome =
            *anyTransient ? ResolutionOutcome::TransientFailure : ResolutionOutcome::PermanentNoService;
        }
        callback(*result, nullptr);
      });

    issueFallbackFamily(domain, families, 0, addresses, finish, anyTransient);
  }

  /// \brief Resolve target addresses asynchronously
  /// \param result Result containing targets to resolve (must be shared_ptr for async safety)
  /// \param callback Result callback
  void resolveTargetAddressesAsync(std::shared_ptr<ServiceResolutionResult> result,
                                   ServiceResolutionCallback callback, bool secure = false)
  {
    if (result->targets.empty())
    {
      callback(*result, nullptr);
      return;
    }

    // remainingTargets starts at N and needs N decrements, so it can only reach 0
    // AFTER every target has been issued -- the completer's erase therefore never
    // races a live per-target index read (tracker 2026-09-25-5 site 1).
    const std::size_t initialTargetCount = result->targets.size();
    auto remainingTargets = std::make_shared<std::atomic<size_t>>(initialTargetCount);

    // Keep the resolver alive across the async A/AAAA callbacks (fire-and-forget).
    auto self = shared_from_this();

    // Families to query per addressResolutionPolicy, in issue order (design (i)):
    // BOTH families for the "First" policies (never AAAA-only-if-A-empty, which drops
    // the dual-stack failover set), one for the "Only" policies. _config is const and
    // read lock-free here (immutable after ctor).
    auto families =
      std::make_shared<std::vector<DnsType>>(familiesInOrder(_config.addressResolutionPolicy));

    // Terminal completer: EXACTLY ONE decrement per target, at the LAST family issued
    // for the policy. The last decrement (acq_rel forms a release-sequence publishing
    // every target's disjoint address writes to this thread) erases empty targets,
    // orders the failover list, and fires the callback once. NOTE: this latch has no
    // callbackFired backstop -- exactly-one-decrement-per-target (guaranteed by
    // issueTargetFamily's fire-callback-XOR-synchronous-throw wrap) is load-bearing for
    // single-fire safety; do not weaken that invariant.
    auto finishTarget = std::make_shared<std::function<void()>>(
      [self, remainingTargets, result, callback, secure]()
      {
        if (remainingTargets->fetch_sub(1, std::memory_order_acq_rel) == 1)
        {
          result->targets.erase(
            std::remove_if(result->targets.begin(), result->targets.end(),
                           [](const ServiceTarget &t) { return t.addresses.empty(); }),
            result->targets.end());
          self->sortTargetsByPriority(*result, secure);
          callback(*result, nullptr);
        }
      });

    for (std::size_t targetIndex = 0; targetIndex < initialTargetCount; ++targetIndex)
    {
      try
      {
        // Pre-issue statements inside the try (TS-C1 wrap boundary = top of loop body):
        // a bad_alloc / DnsQuestion construction throw must still finish the target once.
        std::string hostname = result->targets[targetIndex].hostname;
        issueTargetFamily(result, targetIndex, hostname, families, 0, finishTarget);
      }
      catch (...)
      {
        (*finishTarget)(); // TS-C1: exactly-one decrement even on a mid-loop issue throw
      }
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