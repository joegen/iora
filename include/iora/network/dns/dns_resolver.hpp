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
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
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
///   - authoritative negative (NXDOMAIN / authoritative NODATA:
///     SOA present OR no NS, RFC 2308 §2.2)                => PermanentNoService
/// The CROSS-STEP combination across the RFC 3263 NAPTR→SRV→A/AAAA fall-forward chain
/// (deepest-avenue-supersedes) is a SEPARATE slice (tracker 2026-09-30-1). Interim: a
/// multi-step resolveServiceDomain carries the TERMINAL avenue's per-avenue outcome.
///
/// LIFECYCLE FAULT MAPPING (human decision 2026-09-30, steps-4-8 M-lifecycle): a terminal
/// transport-lifecycle fault ("transport not running"/"stopped") during a service resolution
/// surfaces as an empty result with outcome == PermanentNoService. This is by design (the failover
/// gate defines lifecycle faults as terminal and NOT TransientFailure, and the 3-value enum has no
/// better fit); a SIP consumer should be aware a local teardown reports PermanentNoService, not a
/// distinct "transient/error" state. Distinct lifecycle handling is a possible future refinement.
enum class ResolutionOutcome
{
  Resolved,          ///< Targets were produced (isSuccess()==true).
  TransientFailure,  ///< Server-local/timeout exhausted across all servers — RETRYABLE.
  PermanentNoService ///< Authoritative negative (NXDOMAIN / authoritative NODATA — SOA present or
                     ///< no NS, RFC 2308 §2.2), or a terminal transport-lifecycle fault (see
                     ///< LIFECYCLE FAULT MAPPING above) — no service.
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
///        exhausted on SERVER-LOCAL conditions (SERVFAIL/REFUSED/FORMERR/NOTIMP/ a referral
///        (NS, no SOA) / a truncated (TC=1) / a lame (RA=0,AA=0) empty answer / timeout / network
///        fault) without ever reaching an authoritative response or a success (tracker 2026-09-25-8).
///
/// Distinct TYPE from DnsResolutionFailedException / DnsNoRecordsException (which mark an
/// AUTHORITATIVE negative — NXDOMAIN / authoritative NODATA, SOA present or no NS per RFC 2308
/// §2.2). It derives from DnsResolverException
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

protected:
  /// \brief Tag selecting the pre-built-message forwarding ctor (round-3 cpp17 M-1).
  /// DnsResolverException::_message is private and the public ctor above hardcodes the
  /// "all servers exhausted" prefix, so a subclass (DnsDeadlineException) that needs a
  /// DISTINCT message while remaining IS-A DnsTransientResolutionException forwards its
  /// full pre-built message + code through here. Tag-dispatched to stay distinct from the
  /// public (domain, code) ctor.
  struct FullMessageTag
  {
  };
  DnsTransientResolutionException(FullMessageTag, const std::string &fullMessage,
                                  DnsResponseCode code)
      : DnsResolverException(fullMessage, code)
  {
  }
};

/// \brief Thrown when a per-resolution DEADLINE (DnsConfig::maxResolutionTime or a per-call
///        override) is exceeded, bounding the RFC 3263 NAPTR→SRV→A/AAAA chain under the SIP
///        transaction ceiling (Timer B/F = 64*T1 = 32s). Tracker 2026-09-30-3 (F-2).
///
/// IS-A DnsTransientResolutionException BY DESIGN, so it needs NO new catch site: every
/// fall-forward `catch (const DnsResolverException&)` unwinds it; every OUTCOME-SETTING
/// `catch (const DnsTransientResolutionException&)` (ordered before the DnsResolverException
/// handler) maps it to ResolutionOutcome::TransientFailure; isTransientError() is true for it;
/// resolveHostname folds it into anyTransient. A deadline is thus NEVER PermanentNoService,
/// sync == async.
///
/// Delivered ONLY for the actual deadline sub-case. The all-server EXHAUSTION terminal keeps
/// its OWN DnsTransientResolutionException(qname, lastServerLocalRcode) — do NOT convert
/// exhaustion into a deadline exception (that would break the deadline-OFF path, the per-server
/// rcode fidelity, and sync/async parity — round-2 cpp17 HIGH-A).
class DnsDeadlineException : public DnsTransientResolutionException
{
public:
  explicit DnsDeadlineException(const std::string &domain,
                                DnsResponseCode code = DnsResponseCode::SERVFAIL)
      : DnsTransientResolutionException(FullMessageTag{},
                                        "DNS resolution deadline exceeded for: " + domain, code)
  {
  }
};

/// \brief Thrown by the SYNC query() leaf when a NAPTR query is answered NOTIMP/FORMERR (RFC 3263
///        human decision Q5): the server does not implement NAPTR, so the caller must fall STRAIGHT
///        to direct-SRV WITHOUT rotating servers (they are likely the same infra). It derives from
///        DnsResolverException so the NAPTR step-fallback `catch (const DnsResolverException&)`
///        triggers direct-SRV — but it is a DISTINCT type from DnsTransientResolutionException so a
///        transient-outcome handler (added for the sync per-avenue outcome, tracker 2026-09-25-8)
///        never misclassifies "NAPTR unsupported" as a retryable server outage.
class DnsNaptrUnsupportedException : public DnsResolverException
{
public:
  explicit DnsNaptrUnsupportedException(const std::string &domain, DnsResponseCode code)
      : DnsResolverException("NAPTR not supported (fall to direct-SRV) for: " + domain, code)
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

  /// \brief Worst-case wall-clock of the ONE async issue the per-resolution deadline gate cannot
  ///        abort in flight (tracker 2026-09-30-3, F-2). Delegates to
  ///        DnsTransport::asyncAttemptBudget on the pinned live config snapshot (never a re-derived
  ///        formula — round-2 cpp17 MEDIUM-A). A SIP consumer sizes its deadline D from this so the
  ///        async overhang (worst case = D + this value) still fits under SIP Timer B/F; see
  ///        docs/network/dns_client.md. Returns 0 only when no config snapshot is available (an
  ///        empty server list still yields the full per-issue budget — L-3).
  std::chrono::milliseconds asyncAttemptBudget() const
  {
    auto cfg = _transport->getConfig();
    return cfg ? _transport->asyncAttemptBudget(*cfg) : std::chrono::milliseconds::zero();
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
                       bool secure = false,
                       std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt)
  {
    // Validate input domain
    if (!validateHostname(domain))
    {
      throw DnsResolverException("Invalid hostname: " + sanitizeInput(domain, 100));
    }

    // Compute the absolute per-resolution deadline ONCE (F-2, tracker 2026-09-30-3) and thread it
    // down the RFC 3263 chain. Cache hits below are served regardless of the deadline.
    const auto deadline = computeResolutionDeadline(deadlineOverride);

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

    auto result = performServiceResolution(domain, preferredTransports, secure, deadline);

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
                                 bool secure = false,
                                 std::optional<std::chrono::milliseconds> deadlineOverride =
                                   std::nullopt)
  {
    // Deliver AT MOST ONCE across every path below (cache-hit, fresh, and any TS-M2
    // re-delivery on a throwing callback) -- tracker 2026-09-25-5 steps-4-8 H-1.
    callback = makeSingleFire(std::move(callback));

    // Compute the absolute per-resolution deadline ONCE (F-2) and thread it into the async chain.
    // Cache hits below are served regardless of the deadline.
    const auto deadline = computeResolutionDeadline(deadlineOverride);

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

    // Single-fire the LOG only (tracker 2026-09-30-4 thread-safety LOW-1): a throwing user callback
    // unwinds back into performServiceResolutionAsync's TS-M2 catch, which re-invokes this wrapper.
    // `callback` is already single-fire (installed above), so re-entry cannot double-DELIVER; without
    // this guard it would only emit a spurious second (usually "failed") log line for one resolution.
    auto logged = std::make_shared<std::atomic<bool>>(false);
    performServiceResolutionAsync(
      domain,
      [domain, startTime, callback, logged](const ServiceResolutionResult &result,
                                            std::exception_ptr error)
      {
        // (secure is applied inside performServiceResolutionAsync; this logging wrapper
        // does not re-filter.)
        if (!logged->exchange(true))
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
        }

        callback(result, error);
      },
      preferredTransports, secure, deadline);
  }

  /// \brief Perform standard DNS query, with RFC 1035 §7.2 next-server failover.
  ///
  /// Every delivered response is classified by classifyDelivered() into Positive / Authoritative /
  /// ServerLocal (the single gate shared with the async path). SERVER-LOCAL (rotate to the NEXT
  /// configured server, excluding tried) covers: an rcode-bearing negative
  /// (SERVFAIL/REFUSED/FORMERR/NOTIMP/other error rcode); a referral (NOERROR/empty, NS, no SOA); a
  /// truncated (TC=1) non-positive answer; a lame empty answer (RA=0 AND AA=0, no SOA/NS); a
  /// CNAME-only answer without an SOA; and a thrown transport fault (timeout, connect/send failure,
  /// per-server query-ID exhaustion). AUTHORITATIVE (STOP rotation) covers: NXDOMAIN with RA or AA;
  /// an authoritative NODATA (SOA present, or type-3 empty-authority with RA or AA, RFC 2308 §2.2);
  /// and a CNAME-only answer WITH an SOA. Rotation continues until a Positive answer, an
  /// Authoritative negative, or all servers are exhausted. Server selection is OWNED here (never
  /// getNextServer()): one
  /// getConfig() snapshot pins the server list, and a resolver-owned rotating cursor picks
  /// the starting server (tracker 2026-09-25-8).
  ///
  /// \param question DNS question to resolve
  /// \return DNS query result
  /// \throws DnsResolutionFailedException / DnsNoRecordsException on an AUTHORITATIVE negative
  /// \throws DnsTransientResolutionException when all servers are exhausted on server-local
  ///         conditions (transient, retryable — preserves the transient signal)
  /// \throws DnsTransportException on a TERMINAL lifecycle fault (transport stopped, etc.)
  /// \param deadlineOverride Optional per-call resolution deadline (F-2): nullopt = use
  ///        DnsConfig::maxResolutionTime; an explicit value overrides it (0ms disables for this
  ///        call). Computed to an absolute deadline ONCE here and threaded into queryImpl.
  DnsResult query(const DnsQuestion &question,
                  std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt)
  {
    return queryImpl(question, computeResolutionDeadline(deadlineOverride));
  }

private:
  /// \brief Internal failover-loop impl bounded by an absolute \p deadline (F-2, tracker
  ///        2026-09-30-3). \p deadline is REQUIRED (never defaulted) so a missed threading hop is a
  ///        COMPILE error, not a silent fail-open unbounded query (round-2 cpp17 MEDIUM-1/2). It is
  ///        never recomputed below. Reached via query() (public) or an internal threaded caller.
  DnsResult queryImpl(const DnsQuestion &question, std::chrono::steady_clock::time_point deadline)
  {
    // Cache check ONCE before the failover loop. A negative cache entry is only ever an
    // AUTHORITATIVE negative (cacheQueryResult never caches a no-SOA negative, RFC 2308 §5),
    // so a negative hit is permanent — throw the authoritative exception, never transient.
    if (_cache)
    {
      DnsResult cached;
      if (_cache->get(question, cached))
      {
        // isPositiveAnswer, not isSuccess(): a negatively-cached CNAME-only NODATA is stored with
        // its original ANCOUNT (so isSuccess() is true) but is NOT a positive answer (H-1).
        if (!isPositiveAnswer(question, cached))
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
      // Deadline gate (F-2, tracker 2026-09-30-3): before issuing to THIS server — which covers
      // "before the loop" on i==0 and "before each issue" thereafter — stop if the deadline has
      // passed and throw DnsDeadlineException (IS-A DnsTransientResolutionException -> the RFC 3263
      // chain unwinds to TransientFailure with ZERO further wire queries). Disabled sentinel max()
      // => never fires (byte-for-byte today's behavior). NOT converted from the exhaustion terminal
      // below, which keeps its own DnsTransientResolutionException(qname, lastServerLocalRcode).
      if (deadlineExpired(deadline))
      {
        throw DnsDeadlineException(question.qname);
      }
      // Explicit per-server iteration excluding tried — never getNextServer() (a blind shared
      // round-robin with no failover memory). Each server is contacted at most once.
      const DnsServer &srv = cfg->servers[(start + i) % serverCount];
      try
      {
        // Hard-cap the in-flight wait at the time remaining to the deadline (F-2): a blackholed
        // server cannot make this single wait outlast the deadline. 0 when disabled -> the
        // transport uses its full config-derived budget = today's behavior.
        DnsResult result =
          _transport->query(question, srv.address, srv.port, remainingSyncWait(deadline));

        switch (classifyDelivered(question, result))
        {
        case DeliveredClass::Positive:
          cacheQueryResult(question, result); // terminal (positive) — cache once
          return result;

        case DeliveredClass::Authoritative:
          // NXDOMAIN / authoritative NODATA / CNAME-only-with-SOA -> permanent. STOP rotation; cache
          // the authoritative negative (cacheQueryResult stores only the SOA-bearing subset per
          // RFC 2308 §5, and never a positive CNAME-only entry — H-1) and throw.
          cacheQueryResult(question, result);
          throw DnsResolutionFailedException(question.qname, result.header.rcode);

        case DeliveredClass::ServerLocal:
          // Q5 (human decision 2026-09-30): a NAPTR query answered NOTIMP/FORMERR means the server
          // does not implement NAPTR — the other configured servers are likely the same
          // infrastructure, so do NOT rotate all servers. Fall STRAIGHT to direct-SRV: throw the
          // dedicated DnsNaptrUnsupportedException (a DnsResolverException) after this single NAPTR
          // query so the NAPTR path's step-fallback catch triggers direct-SRV — distinct from the
          // transient type. (NAPTR still rotates on SERVFAIL/REFUSED/timeout — real server-local.)
          if (isNaptrUnsupported(question, result))
          {
            throw DnsNaptrUnsupportedException(question.qname, result.header.rcode);
          }
          // SERVFAIL / REFUSED / FORMERR / NOTIMP / other error rcode / a REFERRAL (NS, no SOA) /
          // TC=1 / lame (RA=0,AA=0) / CNAME-only-without-SOA -> rotate. Never cached.
          lastServerLocalRcode = result.header.rcode;
          break; // break out of the switch; the for-loop rotates to the next server
        }
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

private:
  // ===========================================================================
  // Next-server failover internals (tracker 2026-09-25-8) — resolver-internal, NOT public API.
  // The detection gate, chain state, and the async failover helper live here so consumers cannot
  // reach into the failover machinery (steps-4-8 M-5). The public entry points (query, queryAsync,
  // resolveHostname, resolveServiceDomain[Async]) below/above use them as members.
  // ===========================================================================

  /// \brief Detection gate: is a non-success DnsResult an AUTHORITATIVE negative
  ///        (NXDOMAIN / authoritative NODATA) that must STOP next-server rotation, versus a
  ///        SERVER-LOCAL negative (SERVFAIL/REFUSED/FORMERR/NOTIMP/other error rcode / a
  ///        referral) that must rotate? (tracker 2026-09-25-8, gate corrected 2026-09-30-4 H-1).
  /// \pre not a positive answer for the queried type (isPositiveAnswer(question,result) == false).
  ///      Reached only from classifyDelivered's non-positive, non-CNAME-only branch, where
  ///      result.isSuccess() == false (tracker 2026-09-30-4 LOW-2).
  static bool isAuthoritativeNegative(const DnsResult &result)
  {
    // A truncated response (TC=1) is NEVER evidence of absence (RFC 2181 §9): its sections may be
    // incomplete. Treat it as server-local so the failover rotates (or, in Both/TCP mode, the TCP
    // retry runs) — never authoritative (tracker 2026-09-30-4 F-3). cacheQueryResult likewise
    // refuses to cache a truncated response.
    if (result.header.tc)
    {
      return false;
    }
    const DnsResponseCode rc = result.header.rcode;
    if (rc == DnsResponseCode::NXDOMAIN)
    {
      // An NXDOMAIN is trustworthy only from a server that recursed (RA) or is authoritative (AA):
      // a LAME reply (RA=0 AND AA=0) is not proof the name does not exist -> rotate to a working
      // server (tracker 2026-09-30-4 M-2). The mock/real recursive NXDOMAIN sets RA=1, so it stops.
      return result.header.ra || result.header.aa;
    }
    if (rc == DnsResponseCode::NOERROR)
    {
      // NODATA (NOERROR + no answers). RFC 2308 §2.2: an authoritative NODATA is distinguished
      // from a referral by the "presence of an SOA record ... OR the absence of NS records". So a
      // type-3 NODATA (empty authority: no SOA and no NS) IS authoritative — the name exists but
      // has no records of this type, and rotating to other recursive servers cannot change that.
      // A referral (NS present, no SOA) is NOT authoritative here — treat it server-local so the
      // failover rotates. SOA-gating is a CACHING concern only (cacheQueryResult / RFC 2308 §5),
      // NOT the authority test — the pre-fix SOA-only gate mis-classified the common
      // dnsmasq/GSLB NOERROR/empty/no-SOA (typical for AAAA/SRV/NAPTR) as a retryable outage.
      if (negativeResponseHasSoa(result))
      {
        return true;
      }
      // The type-3 (empty-authority) heuristic presumes a server that actually recursed or is
      // authoritative. A LAME reply (RA=0 AND AA=0) with empty authority is not trustworthy
      // evidence of absence — treat it server-local so the failover reaches a working server
      // (tracker 2026-09-30-4 F-4). The dnsmasq/GSLB case H-1 targets sets RA=1, so it still stops.
      return !authorityHasNs(result) && (result.header.ra || result.header.aa);
    }
    // SERVFAIL, REFUSED, FORMERR, NOTIMP, and any other error rcode are server-local.
    return false;
  }

  /// \brief RFC 3263 human-decision Q5: a NAPTR query answered NOTIMP/FORMERR means the server
  ///        does not implement NAPTR -> fall STRAIGHT to direct-SRV without rotating servers. One
  ///        predicate shared by the sync query() leaf and the async classifyAsyncCompletion so the
  ///        two cannot drift (tracker 2026-09-25-8).
  static bool isNaptrUnsupported(const DnsQuestion &question, const DnsResult &result)
  {
    return question.qtype == DnsType::NAPTR &&
           (result.header.rcode == DnsResponseCode::NOTIMP ||
            result.header.rcode == DnsResponseCode::FORMERR);
  }

  /// \brief Per-failover-chain state for one INDEPENDENT async transport issue (tracker
  ///        2026-09-25-8). A and AAAA are separate issues, so the failover unit is the
  ///        per-family issue, NOT the target slot — each gets its own chain.
  ///
  /// Heap-allocated (make_shared) and captured BY VALUE into every helper/re-issue lambda,
  /// alongside self = shared_from_this(). Servers are visited in the fixed cyclic order
  /// (startIndex + attempts) % n, so a monotonic `attempts` counter both selects the next server
  /// and bounds the chain (exhausted when attempts >= n) — no per-server "tried" set is needed.
  /// Only ONE thread touches these fields at a time: the per-issue CAS handshake in
  /// queryAsyncWithFailover hands the chain from the issuing thread to a completion thread (or
  /// back) at a single acq_rel point, which also publishes these fields — so they need no atomics,
  /// but they MUST live here (heap), never as stack locals.
  struct FailoverChainState
  {
    std::shared_ptr<const DnsConfig> snapshot; ///< pinned server list (one snapshot per chain)
    std::size_t startIndex{0};                  ///< rotating start server (load spread)
    std::size_t attempts{0};                    ///< servers tried so far; exhausted when >= size
    /// Last server-local rcode seen (L-2): tags the terminal transient exception faithfully
    /// instead of a hardcoded SERVFAIL. Written before the CAS on the advancing hop and read at
    /// exhaustion on the same hop / a later hop — ordered by the same acq_rel CAS that publishes
    /// `attempts`, so no atomic needed.
    DnsResponseCode lastServerLocalRcode{DnsResponseCode::SERVFAIL};
    /// Absolute per-resolution deadline (F-2, tracker 2026-09-30-3). Write-once at
    /// makeFailoverChain (construction happens-before every read via the shared_ptr capture /
    /// register->complete acq_rel edge), so no atomic is needed. Default max() = disabled = the
    /// async gate's deadline branch never fires. Read at the queryAsyncWithFailover loop top.
    std::chrono::steady_clock::time_point deadline{
      (std::chrono::steady_clock::time_point::max)()};
  };

  // ===========================================================================
  // Per-resolution DEADLINE helpers (tracker 2026-09-30-3, F-2)
  //
  // The absolute deadline is computed ONCE at each PUBLIC entry (from a per-call override or
  // DnsConfig::maxResolutionTime) and threaded DOWN as a required by-value time_point through
  // every internal impl (sync) / FailoverChainState (async). A budget of 0 (the default) yields
  // the DISABLED sentinel time_point::max(), so every gate below is a no-op and behavior is
  // byte-for-byte unchanged. Steady clock ONLY (monotonic; no wall-clock jumps). By value, never
  // a resolver member: the resolver is long-lived and shared, so a member time_point would tear
  // across concurrent resolutions.
  // ===========================================================================

  /// \brief The DISABLED sentinel: deadline == max() means "no deadline" (gates never fire).
  static constexpr std::chrono::steady_clock::time_point noDeadline()
  {
    return (std::chrono::steady_clock::time_point::max)();
  }

  /// \brief Emit a deadline-MISCONFIGURATION WARNING at most once (per \p latch). FULLY NO-THROW
  ///        (cpp17 round-3 L-1): the \p latch is claimed FIRST, then the detail string is BUILT AND
  ///        logged INSIDE the try — the string concatenation (a bad_alloc source) must not escape,
  ///        because computeResolutionDeadline runs at the top of the async public entries whose
  ///        deliver-via-callback contract a throw would break. \p buildDetail is invoked only on the
  ///        once-per-latch path (no wasted allocation after the latch fires).
  template <class BuildDetail>
  void warnDeadlineMisconfigOnce(std::atomic<bool> &latch, BuildDetail buildDetail) const
  {
    if (latch.exchange(true, std::memory_order_relaxed))
    {
      return; // already warned once through this latch
    }
    try
    {
      iora::core::Logger::warning("DNS per-resolution deadline " + buildDetail());
    }
    catch (...)
    {
    }
  }

  /// \brief Compute the absolute deadline for one resolution. A per-call \p deadlineOverride wins
  ///        over the live config's maxResolutionTime (nullopt => use config). Reads ONE live
  ///        transport config snapshot (INV-2), same source as the server list / async budget.
  ///
  /// Budget semantics:
  /// - == 0  => DISABLED (noDeadline(), the default) — byte-for-byte today's behavior.
  /// - <  0  => a MISCONFIGURATION (HIGH-A). Most commonly a consumer computed
  ///            D = Timer_B/F - asyncAttemptBudget() - margin and it UNDERFLOWED negative — note the
  ///            DEFAULT config's asyncAttemptBudget() EXCEEDS Timer B (64*T1=32s), so no D fits at
  ///            defaults; reduce DnsConfig.timeout/retryCount (see docs/network/dns_client.md). A
  ///            negative budget FAILS CLOSED to an already-expired deadline: the resolution returns
  ///            TransientFailure (retryable), NEVER an unbounded resolution past Timer B. The SIP
  ///            response mapping is the adapter's job (iora_sip 2026-09-25-2), NOT this layer's: a
  ///            UAC maps a transport/DNS failure to a local 503 (RFC 3261 §8.1.3.1); a PROXY should
  ///            NOT forward a blanket 503 upstream for one failed target (RFC 3261 §16.7 step 6 — an
  ///            upstream RFC 3263 §4.3 client would blacklist the whole proxy) and should use 500/504
  ///            (§21.5.5) instead. Reserve 503 upstream for a condition affecting every request.
  /// - >  0  => now() + budget, SATURATING to disabled if it would overflow the steady_clock ns rep
  ///            (H-1: now()+ms::max() is signed-overflow UB wrapping into the past).
  std::chrono::steady_clock::time_point
  computeResolutionDeadline(std::optional<std::chrono::milliseconds> deadlineOverride) const
  {
    const auto cfg = _transport->getConfig(); // ONE snapshot (INV-2)
    const std::chrono::milliseconds budget =
      deadlineOverride ? *deadlineOverride
                       : (cfg ? cfg->maxResolutionTime : std::chrono::milliseconds::zero());

    if (budget == std::chrono::milliseconds::zero())
    {
      return noDeadline(); // explicit 0 = disabled
    }
    if (budget < std::chrono::milliseconds::zero())
    {
      // Fail CLOSED (HIGH-A): return an already-expired deadline -> the first server-loop / async
      // gate throws DnsDeadlineException -> TransientFailure, never an unbounded resolution.
      warnDeadlineMisconfigOnce(_negativeDeadlineWarned, [budget]
                                {
                                  return "is negative (" + std::to_string(budget.count()) +
                                         "ms): failing closed, every non-cached resolution returns "
                                         "TransientFailure until DnsConfig.maxResolutionTime / the "
                                         "per-call override is corrected (the default config cannot "
                                         "meet SIP Timer B; reduce DnsConfig.timeout/retryCount).";
                                });
      return std::chrono::steady_clock::now(); // now => deadlineExpired() true at the first gate
    }

    // budget > 0. Is the deadline below one server's BLACKHOLE cost (the UDP-retransmit budget, NOT
    // asyncAttemptBudget(cfg) which includes the TC=1->TCP-fallback leg — a blackholed server never
    // sends TC=1, sip-voip MEDIUM-1)? Below it, a dead server exhausts the deadline before the next
    // server is tried -> RFC 1035 §7.2 failover is defeated (per-server sub-budget -> 2026-09-30-5).
    // The check runs each budget>0 resolution UNTIL it warns once, so a later smaller override or an
    // updateConfig() shrink is still caught (cpp17 M-2); once warned, the cost stops (cpp17 L-2b).
    if (cfg && !_subBudgetWarned.load(std::memory_order_relaxed))
    {
      const auto perServerBudget = _transport->udpAttemptBudget(*cfg);
      if (budget < perServerBudget)
      {
        warnDeadlineMisconfigOnce(
          _subBudgetWarned, [budget, perServerBudget]
          {
            return "(" + std::to_string(budget.count()) +
                   "ms) is below one server's UDP-retransmit budget (" +
                   std::to_string(perServerBudget.count()) +
                   "ms): a dead server exhausts the deadline before the next server is tried, so "
                   "next-server failover (RFC 1035 §7.2) may be defeated. Reduce "
                   "DnsConfig.timeout/retryCount, or track per-server sub-budgeting (2026-09-30-5).";
          });
      }
    }

    const auto now = std::chrono::steady_clock::now();
    // Headroom to the sentinel, as milliseconds; if the budget meets/exceeds it, saturate to
    // "disabled" instead of overflowing (max() - now() cannot overflow — max() is the largest rep).
    const auto headroom =
      std::chrono::duration_cast<std::chrono::milliseconds>(noDeadline() - now);
    return (budget >= headroom) ? noDeadline() : now + budget;
  }

  /// \brief True iff the deadline has passed (always false for the disabled sentinel, since
  ///        now() >= max() is never true — no special-case needed).
  static bool deadlineExpired(std::chrono::steady_clock::time_point deadline)
  {
    return std::chrono::steady_clock::now() >= deadline;
  }

  /// \brief The per-call maxWait to hand DnsTransport::query so an in-flight sync wait cannot
  ///        overrun the deadline. 0 when disabled (transport uses its full config budget). The
  ///        max()-guard MUST precede the subtraction: max() - now() overflows the duration rep
  ///        (UB). Callers gate with deadlineExpired() first, so remaining is > 0 here; clamp to
  ///        >= 1ms defensively so a just-at-deadline call still passes a positive cap.
  ///
  /// Rounds UP with std::chrono::ceil, NOT duration_cast (M-1): truncation would hand the transport
  /// a wait ending a sub-millisecond BEFORE the deadline, so the next step's deadlineExpired() gate
  /// would miss and one extra wire query would be issued past the deadline. Ceiling makes wait_for
  /// end at or after the deadline, so the gate always fires — the "zero further wire queries after
  /// expiry" contract becomes deterministic.
  static std::chrono::milliseconds remainingSyncWait(std::chrono::steady_clock::time_point deadline)
  {
    if (deadline == noDeadline())
    {
      return std::chrono::milliseconds::zero();
    }
    auto remaining =
      std::chrono::ceil<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    return (remaining > std::chrono::milliseconds::zero()) ? remaining
                                                           : std::chrono::milliseconds{1};
  }

  /// \brief Build a fresh failover chain: pin one getConfig() snapshot and pick a rotating
  ///        starting server from the resolver-owned cursor. An empty/absent snapshot yields a
  ///        chain that is immediately exhausted (attempts 0 >= size 0) -> the helper funnels a
  ///        terminal transient (never a silent empty). \p deadline (F-2) is a REQUIRED by-value
  ///        param (never defaulted) so the compiler forces every async carrier to thread it into
  ///        the chain's write-once deadline field.
  std::shared_ptr<FailoverChainState>
  makeFailoverChain(std::chrono::steady_clock::time_point deadline)
  {
    auto chain = std::make_shared<FailoverChainState>();
    chain->snapshot = _transport->getConfig();
    chain->deadline = deadline;
    const std::size_t n = (chain->snapshot ? chain->snapshot->servers.size() : 0);
    chain->startIndex =
      (n > 0 ? (_serverRotation.fetch_add(1, std::memory_order_relaxed) % n) : 0);
    return chain;
  }

  /// \brief Async detection gate: does an async completion (result,error) mean "rotate to the
  ///        next server" (server-local) or "deliver terminal"? Mirrors the sync gate.
  enum class AsyncFailoverVerdict
  {
    Terminal,        ///< success / authoritative-negative / lifecycle fault / Q5 -> deliver as-is
    ServerLocalRetry ///< SERVFAIL/REFUSED/FORMERR/NOTIMP/referral/TC=1/lame/timeout/network -> rotate
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
    // A delivered result (no error) — classified by the SAME gate as the sync leaf so the two
    // cannot drift (tracker 2026-09-30-4 H-1/M-1).
    switch (classifyDelivered(question, result))
    {
    case DeliveredClass::Positive:
    case DeliveredClass::Authoritative:
      return AsyncFailoverVerdict::Terminal;
    case DeliveredClass::ServerLocal:
      // Q5: a NAPTR answered NOTIMP/FORMERR means "NAPTR unsupported" — deliver as-is so the NAPTR
      // completer falls straight to direct-SRV, WITHOUT rotating all servers (they are likely the
      // same infra). Everything else server-local (SERVFAIL/REFUSED/FORMERR/referral/TC=1/lame/
      // CNAME-only-without-SOA) rotates.
      return isNaptrUnsupported(question, result) ? AsyncFailoverVerdict::Terminal
                                                  : AsyncFailoverVerdict::ServerLocalRetry;
    }
    return AsyncFailoverVerdict::ServerLocalRetry; // unreachable (all enum cases handled)
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

  /// \brief The outcome for an avenue that produced NO usable target: TransientFailure (retryable)
  ///        if any server-local exhaustion occurred, else PermanentNoService (authoritative). One
  ///        named policy so the several empty-result sites cannot drift (steps-4-8 L-A).
  static ResolutionOutcome noServiceOutcome(bool anyTransient)
  {
    return anyTransient ? ResolutionOutcome::TransientFailure : ResolutionOutcome::PermanentNoService;
  }

  /// \brief One SYNC policy for an SRV avenue that produced NO targets (tracker 2026-09-30-4 H-A):
  ///        if any SRV set exhausted server-local, carry TransientFailure and SUPPRESS the
  ///        RFC 3263 §4.2 apex fallback (a transient is not proof of absence — M-4); otherwise do
  ///        the §4.2 A/AAAA fallback of the domain on \p transports (NAPTR-chosen or the direct-SRV
  ///        preferred set), honoring RFC 2782 "." suppression via \p denied. Shared by the
  ///        direct-SRV and NAPTR-S paths so the two cannot drift (the drift that caused F-5). The
  ///        fallback targets are LEFT in \p transports order (already preference-ordered) and NOT
  ///        re-sorted — a later sortTargetsByPriority would reorder them by ServiceType enum value
  ///        and discard NAPTR preference, diverging from the async path (F-5).
  void resolveEmptySrvAvenue(const std::string &domain, ServiceResolutionResult &result,
                             bool anySrvTransient, const std::vector<ServiceType> &transports,
                             const std::vector<ServiceType> &denied, bool secure,
                             std::chrono::steady_clock::time_point deadline)
  {
    if (anySrvTransient)
    {
      result.outcome = ResolutionOutcome::TransientFailure;
    }
    else
    {
      performFallbackResolution(domain, result, transports, denied, secure, deadline);
    }
  }

  /// \brief ASYNC completer for an SRV join (tracker 2026-09-30-4 H-A): the async twin of
  ///        resolveEmptySrvAvenue plus the non-empty branch. Fires \p callback EXACTLY once via
  ///        the delivery path each branch selects. Shared by the direct-SRV and NAPTR-S completers
  ///        so their empty-result policy cannot drift. Precedence: targets → transient → §4.2
  ///        authoritative fallback. Neither delivery path re-sorts, so the fallback keeps
  ///        \p transports (preference) order — matching the sync path (F-5 parity).
  void completeSrvJoinAsync(const std::string &domain, std::shared_ptr<ServiceResolutionResult> result,
                            ServiceResolutionCallback callback, bool anySrvTransient,
                            const std::vector<ServiceType> &transports,
                            const std::vector<ServiceType> &denied, bool secure,
                            std::chrono::steady_clock::time_point deadline)
  {
    if (!result->targets.empty())
    {
      resolveTargetAddressesAsync(result, callback, secure, deadline);
    }
    else if (anySrvTransient)
    {
      // Suppress the §4.2 fallback and carry TransientFailure; resolveTargetAddressesAsync-over-empty
      // preserves the non-Resolved outcome and fires the callback exactly once (M-4).
      result->outcome = ResolutionOutcome::TransientFailure;
      resolveTargetAddressesAsync(result, callback, secure, deadline);
    }
    else
    {
      performFallbackResolutionAsync(domain, result, callback, transports, denied, secure, deadline);
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
  /// is reachable only for PRE-CALL throws. \p wrappedCallback runs with no resolver lock held
  /// (the caller must not hold *resultMutex across this — AP-1).
  ///
  /// SYNC-vs-ASYNC advance (steps-4-8 C-1 fix): whether the issuing thread or the completion
  /// thread drives the next-server advance is resolved by a PER-ISSUE atomic CAS gate `issued`
  /// (0=PENDING, 1=CB_WANTS_ADVANCE, 2=ISSUER_DONE), captured by value into the callback. The
  /// prior plain-bool issuing/advance handshake was a cross-thread data race (the epilogue write
  /// was not covered by the transport's register->complete happens-before edge) that could lose
  /// the advance and hang. The CAS is the single ordered decision point: exactly one of
  /// {issuer continues the loop, callback re-enters} advances, on every interleaving — and the
  /// acq_rel CAS also publishes the chain fields between whichever two threads hand off. A
  /// synchronous completion advances via the loop (no deep self-recursion); a genuine async
  /// completion re-enters once per hop on the worker thread (stack already unwound).
  void queryAsyncWithFailover(const DnsQuestion &question,
                              const std::shared_ptr<FailoverChainState> &chain,
                              QueryCallback wrappedCallback)
  {
    auto self = shared_from_this();
    // Per-issue CAS handshake states (L-3): resolves "who advances" at one atomic point.
    enum : int
    {
      HANDOFF_PENDING = 0,      ///< no party has claimed the advance yet
      HANDOFF_CB_ADVANCE = 1,   ///< the completion callback claimed it (synchronous completion)
      HANDOFF_ISSUER_DONE = 2   ///< the issuer epilogue claimed it (async in flight / terminal fired)
    };
    // Every terminal delivery of \p wrappedCallback is funnelled through this guard: a THROWING
    // user callback is a handled condition (see makeSingleFire), and the helper must NEVER let a
    // callback throw propagate to its caller — otherwise the public-twin site catch(...) would
    // re-deliver it (a double-fire) and the no-backstop finishTarget site would double-decrement
    // (steps-4-8 M-1). The transport's leaf catch(...) protects the ASYNC completion path; this
    // guard protects the issuer-thread paths (exhaustion, synchronous terminal, issue-throw).
    auto deliver = [&wrappedCallback](const DnsResult &r, const std::exception_ptr &e)
    {
      try
      {
        wrappedCallback(r, e);
      }
      catch (...)
      {
      }
    };
    while (true)
    {
      // Branch precedence (L-1): exhaustion is checked BEFORE the deadline. When both would trip on
      // the same loop turn (the last server tried AND the deadline passed), exhaustion wins so the
      // terminal carries the faithful per-server lastServerLocalRcode rather than the generic
      // deadline SERVFAIL — richer diagnostics, and both deliver TransientFailure so the SIP-visible
      // outcome is identical either way.
      const std::size_t n = (chain->snapshot ? chain->snapshot->servers.size() : 0);
      if (chain->attempts >= n)
      {
        // Empty snapshot (n==0) OR all servers exhausted on server-local conditions -> terminal
        // transient (retryable), delivered EXACTLY ONCE. Never a silent empty (ts-LOW-1). The
        // exception construction (string concat) is guarded too (LOW-1): a bad_alloc here on an
        // async re-entry would otherwise be swallowed by the transport leaf catch and hang the
        // no-backstop latch — so an OOM still yields exactly one terminal delivery.
        std::exception_ptr transientEx;
        try
        {
          transientEx = std::make_exception_ptr(
            DnsTransientResolutionException(question.qname, chain->lastServerLocalRcode));
        }
        catch (...)
        {
          transientEx = std::current_exception();
        }
        deliver(DnsResult{}, transientEx);
        return;
      }

      // Deadline gate (F-2, tracker 2026-09-30-3): a SEPARATE branch from exhaustion above, sharing
      // the guarded deliver() funnel but NOT merged with it (round-2 cpp17 HIGH-A — merging would
      // deliver a DnsDeadlineException for pure exhaustion too, breaking the deadline-OFF path, the
      // per-server rcode fidelity, and sync/async parity). Once the deadline has passed, stop issuing
      // further servers/families WITHOUT a wire query and deliver a terminal DnsDeadlineException
      // (IS-A transient -> outcome TransientFailure, never Permanent). This is how "cut both A and
      // AAAA" is realized: the next family chains through queryAsyncWithFailover, hits this branch,
      // and its error-channel callback marks the target transient (issues zero wire queries). It does
      // NOT abort the one query already in flight (soft async bound; worst-case overhang = deadline +
      // asyncAttemptBudget()). Disabled sentinel max() => deadlineExpired() is always false => no-op.
      // Its own guarded make_exception_ptr (this branch returns, so it cannot share the exhaustion
      // branch's try block — round-3 cpp17 L-3): an OOM here still yields exactly one terminal.
      if (deadlineExpired(chain->deadline))
      {
        std::exception_ptr deadlineEx;
        try
        {
          deadlineEx = std::make_exception_ptr(DnsDeadlineException(question.qname));
        }
        catch (...)
        {
          deadlineEx = std::current_exception();
        }
        deliver(DnsResult{}, deadlineEx);
        return;
      }

      // Per-issue CAS handshake resolving "who advances" at ONE atomic point. Declared before the
      // try so the epilogue can read it; assigned inside so a setup throw (bad_alloc) is caught.
      std::shared_ptr<std::atomic<int>> issued;
      try
      {
        // Servers visited in fixed cyclic order; the counter both selects and bounds (each server
        // contacted at most once). getNextServer() is never called here. Setup is INSIDE the try so
        // a throw here (e.g. bad_alloc on an async re-entry, where the transport leaf catch would
        // otherwise swallow it and hang the no-backstop latch) becomes exactly one terminal deliver.
        const DnsServer server =
          chain->snapshot->servers[(chain->startIndex + chain->attempts) % n];
        ++chain->attempts;
        issued = std::make_shared<std::atomic<int>>(HANDOFF_PENDING);
        // The transport mints a fresh unique query id per issue (generateUniqueQueryId), so each
        // re-issue is a distinct in-flight query the transport dedups exactly-once. Pass the
        // explicit server+port so failover actually targets a DIFFERENT server.
        _transport->queryAsync(
          question,
          [self, chain, question, wrappedCallback, issued](const DnsResult &result,
                                                           const std::exception_ptr &error)
          {
            if (classifyAsyncCompletion(question, result, error) ==
                AsyncFailoverVerdict::ServerLocalRetry)
            {
              // Record the last server-local rcode for a faithful terminal transient (L-2).
              // Written before this hop's CAS; read at exhaustion on the same/next hop — ordered by
              // the acq_rel CAS handoff (same as `attempts`), so no atomic needed. An error-channel
              // server-local (timeout/network, no rcode) records SERVFAIL, mirroring the sync leaf.
              chain->lastServerLocalRcode =
                (error == nullptr) ? result.header.rcode : DnsResponseCode::SERVFAIL;
              int expected = HANDOFF_PENDING;
              if (issued->compare_exchange_strong(expected, HANDOFF_CB_ADVANCE,
                                                  std::memory_order_acq_rel))
              {
                // Issuer has NOT yet finished the issue call (synchronous completion): it will
                // observe HANDOFF_CB_ADVANCE in its epilogue and advance via the loop. Do nothing.
              }
              else
              {
                // expected == HANDOFF_ISSUER_DONE: the issuer already returned from the issue call
                // (asynchronous completion) -> WE own the advance. Re-enter to the next server.
                // Guard the re-entry (LOW-1): a bad_alloc copying wrappedCallback on this worker
                // thread would otherwise be swallowed by the transport leaf catch and hang the
                // no-backstop latch; deliver exactly one terminal instead.
                try
                {
                  self->queryAsyncWithFailover(question, chain, wrappedCallback);
                }
                catch (...)
                {
                  try
                  {
                    wrappedCallback(DnsResult{}, std::current_exception());
                  }
                  catch (...)
                  {
                  }
                }
              }
            }
            else
            {
              // Terminal: success / authoritative-negative / lifecycle fault / Q5. Deliver exactly
              // once, swallowing a throwing user callback (no lock held, HR-3). For a SYNCHRONOUS
              // terminal this runs inside the issuer's try; the guard stops it re-firing via the
              // catch(...) below.
              try
              {
                wrappedCallback(result, error);
              }
              catch (...)
              {
              }
            }
          },
          server.address, server.port);
      }
      catch (const DnsTimeoutException &)
      {
        chain->lastServerLocalRcode = DnsResponseCode::SERVFAIL; // L-2 parity with the sync leaf
        continue; // synchronous server-local issue-throw (callback never armed) -> advance
      }
      catch (const DnsNetworkException &)
      {
        chain->lastServerLocalRcode = DnsResponseCode::SERVFAIL; // L-2 parity with the sync leaf
        continue; // synchronous per-server network issue-throw (e.g. query-ID exhaustion) -> advance
      }
      catch (...)
      {
        // Any other synchronous SETUP/ISSUE throw (lifecycle DnsTransportException, std::bad_alloc,
        // a test double's injected throw) is TERMINAL -> exactly ONE deliver. NEVER rethrow (the
        // no-backstop finishTarget latch depends on fire-XOR-nothing here). The transport throws
        // only before arming the callback, so no handshake state is consumed. (A throwing user
        // callback on the synchronous-terminal path is already swallowed above, so it never reaches
        // this catch — no double-fire.)
        deliver(DnsResult{}, std::current_exception());
        return;
      }

      // Issuer epilogue: resolve the handshake. Claiming HANDOFF_ISSUER_DONE means the callback
      // has not yet driven a server-local advance -> async issue in flight (the callback will
      // re-enter on completion) OR a terminal already fired synchronously -> return. If the CAS
      // fails, the callback already completed synchronously server-local (HANDOFF_CB_ADVANCE) -> advance.
      int expected = HANDOFF_PENDING;
      if (issued->compare_exchange_strong(expected, HANDOFF_ISSUER_DONE, std::memory_order_acq_rel))
      {
        return;
      }
      continue; // expected == HANDOFF_CB_ADVANCE: synchronous server-local completion asked to advance
    }
  }

public:
  /// \brief Perform DNS query asynchronously
  /// \param question DNS question to resolve
  /// \param callback Callback function for result
  void queryAsync(const DnsQuestion &question, QueryCallback callback,
                  std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt)
  {
    // Compute the absolute per-resolution deadline ONCE (F-2); cache hits are served regardless.
    const auto deadline = computeResolutionDeadline(deadlineOverride);

    // Check cache first
    if (_cache)
    {
      DnsResult result;
      if (_cache->get(question, result))
      {
        // isPositiveAnswer, not isSuccess(): parity with the sync cache-hit path (H-1) — a
        // negatively-cached CNAME-only NODATA reports isSuccess() but must deliver the exception.
        if (!isPositiveAnswer(question, result))
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
    // propagates a throw, so this try only guards the PRE-CALL statement makeFailoverChain()
    // (shared_from_this above cannot throw for a shared_ptr-owned resolver); a synchronous
    // issue-throw is funneled into the callback by the helper.
    auto self = shared_from_this();
    try
    {
      auto chain = makeFailoverChain(deadline);
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

          // isPositiveAnswer, not isSuccess(): a CNAME-only NODATA delivered as Terminal by
          // classifyAsyncCompletion must be delivered as an ERROR, matching the sync leaf (H-1).
          if (!isPositiveAnswer(question, result))
          {
            // Parity with the sync leaf (LOW-1): a NAPTR NOTIMP/FORMERR is "NAPTR unsupported",
            // not an authoritative negative — deliver the dedicated type so an async caller can
            // tell it apart from NXDOMAIN.
            auto dns_ex = isNaptrUnsupported(question, result)
                            ? std::make_exception_ptr(
                                DnsNaptrUnsupportedException(question.qname, result.header.rcode))
                            : std::make_exception_ptr(
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
  std::vector<std::string>
  resolveHostname(const std::string &hostname, bool prefer_ipv6 = false,
                  std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt)
  {
    return resolveHostnameImpl(hostname, prefer_ipv6, computeResolutionDeadline(deadlineOverride));
  }

private:
  /// \brief Internal resolveHostname impl bounded by an absolute \p deadline (F-2, tracker
  ///        2026-09-30-3). \p deadline is REQUIRED (never defaulted) so a missed threading hop is a
  ///        COMPILE error, not a silent fail-open (round-2 cpp17 LOW-A). Reached via resolveHostname()
  ///        (public) or an internal threaded caller (resolveTargetAddresses / performFallbackResolution).
  std::vector<std::string> resolveHostnameImpl(const std::string &hostname, bool prefer_ipv6,
                                               std::chrono::steady_clock::time_point deadline)
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
        DnsResult ipv4Result = queryImpl(DnsQuestion(hostname, DnsType::A, DnsClass::IN), deadline);
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
        // IPv4 query hit an AUTHORITATIVE negative (NXDOMAIN / authoritative NODATA), continue.
      }
      catch (const DnsTransportException &)
      {
        // A TERMINAL lifecycle fault (transport stopped, etc.). Per-family timeouts no longer
        // reach here (query() rotates and converts them to the transient exception above);
        // keep any partial results and continue to AAAA.
      }
      catch (const DnsParseException &)
      {
        // Reachable for an UNENCODABLE query name: DnsMessage::encodeName throws
        // DnsParseException before any send (e.g. a name in the 254-255 char window
        // that passes validateHostname but exceeds encodeName's 253-octet bound, or a
        // label > 63 bytes). Not a server-local fault -> does not rotate; absorb it as
        // a per-family failure, keep any partial results and continue to AAAA.
      }
    }

    // Query AAAA records (IPv6) if policy allows
    if (policy == AddressResolutionPolicy::IPv6Only ||
        policy == AddressResolutionPolicy::IPv4First ||
        policy == AddressResolutionPolicy::IPv6First)
    {
      try
      {
        DnsResult ipv6Result =
          queryImpl(DnsQuestion(hostname, DnsType::AAAA, DnsClass::IN), deadline);
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
        // Reachable for an unencodable query name (encodeName throws before send; see the
        // IPv4 note above). Not a server-local fault; keep the A results already collected
        // and continue.
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

public:
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
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries = std::nullopt,
    bool secure = false,
    std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt)
  {
    // PUBLIC entry (reached directly by DnsClient::resolveCustomServiceDomain): compute the
    // absolute deadline ONCE (F-2) and delegate to the deadline-threading impl. Internal callers
    // that already hold a threaded deadline (e.g. the NAPTR direct-SRV fallback) call the Impl
    // directly so the clock is NOT reset mid-chain.
    return performDirectSrvResolutionImpl(domain, preferredTransports, srvQueries, secure,
                                          computeResolutionDeadline(deadlineOverride));
  }

private:
  /// \brief Deadline-threading impl for direct-SRV resolution (F-2). \p deadline REQUIRED
  ///        (never defaulted) so a missed hop is a compile error, not a fail-open. PRIVATE: only
  ///        the public entry (which computes the deadline once) and internal threaded callers reach
  ///        it (cpp17 M-2 / simpl LOW-7 — external code must not pass a raw time_point{} = epoch).
  ServiceResolutionResult performDirectSrvResolutionImpl(
    const std::string &domain, const std::vector<ServiceType> &preferredTransports,
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries,
    bool secure, std::chrono::steady_clock::time_point deadline)
  {
    ServiceResolutionResult result(domain);

    auto actualSrvQueries = buildOrderedSrvQueries(domain, srvQueries, preferredTransports, secure);

    // Query SRV records. Track which services returned an RFC 2782 "." abort so the
    // A/AAAA fallback is suppressed per-service (not domain-wide).
    std::vector<ServiceType> deniedServices;
    // Track whether ANY SRV set exhausted all servers on server-local conditions (transient).
    // A transient SRV outage is NOT proof the SRV records are absent, so the bare-domain A/AAAA
    // fallback MUST be suppressed and the outcome carried as TransientFailure — RFC 3263 §4.2
    // fallback is conditioned on ABSENCE, not on SERVFAIL (tracker 2026-09-30-4 M-4).
    bool anySrvTransient = false;
    // The query's index in the preference-ordered actualSrvQueries is the per-set transport
    // rank, stamped as naptrPreference so sortTargetsByPriority sequences transports per set
    // and never cross-compares SRV priority across owner names (2026-09-25-4 fix A).
    for (std::size_t rank = 0; rank < actualSrvQueries.size(); ++rank)
    {
      const auto &srvName = actualSrvQueries[rank].first;
      const auto service = actualSrvQueries[rank].second;
      try
      {
        DnsResult srvResult = queryImpl(DnsQuestion(srvName, DnsType::SRV, DnsClass::IN), deadline);
        if (processSrvRecords(srvResult.srv_records, service, result,
                              static_cast<std::uint16_t>(rank)))
        {
          deniedServices.push_back(service);
        }
      }
      catch (const DnsTransientResolutionException &)
      {
        // This SRV set exhausted all servers on server-local conditions (transient). Skip the set
        // (RFC 3263 §4.3) but remember it so an empty result carries TransientFailure and the
        // bare-domain A/AAAA fallback is suppressed (tracker 2026-09-30-4 M-4).
        anySrvTransient = true;
        continue;
      }
      catch (const DnsResolverException &)
      {
        // Skip failed queries (authoritative negative / other resolver failure)
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
        // Reachable for an unencodable SRV query name (encodeName throws before send). Not a
        // server-local fault; skip this SRV set, keep the others (RFC 3263 §4.3).
        continue;
      }
    }

    if (!result.targets.empty())
    {
      resolveTargetAddresses(result, deadline);
      sortTargetsByPriority(result, secure);
    }
    else
    {
      // No SRV targets: carry TransientFailure on a transient exhaustion, else the RFC 3263 §4.2
      // A/AAAA domain fallback (RFC 2782 "." honored) — one shared policy with the NAPTR-S path
      // (tracker 2026-09-30-4 M-4/H-A). The fallback keeps preferred-transport order (not re-sorted).
      resolveEmptySrvAvenue(domain, result, anySrvTransient, preferredTransports, deniedServices,
                            secure, deadline);
    }

    return result;
  }

public:
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
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries = std::nullopt,
    bool secure = false,
    std::optional<std::chrono::milliseconds> deadlineOverride = std::nullopt)
  {
    // PUBLIC entry (reached directly by DnsClient::resolveCustomServiceDomainAsync): compute the
    // absolute deadline ONCE (F-2) and delegate to the deadline-threading impl. Internal callers
    // holding a threaded deadline call the Impl directly (no mid-chain clock reset).
    performDirectSrvResolutionAsyncImpl(domain, std::move(callback), preferredTransports, srvQueries,
                                        secure, computeResolutionDeadline(deadlineOverride));
  }

private:
  /// \brief Deadline-threading impl for async direct-SRV resolution (F-2). \p deadline REQUIRED.
  ///        PRIVATE (cpp17 M-2 / simpl LOW-7): only the public entry + internal threaded callers.
  void performDirectSrvResolutionAsyncImpl(
    const std::string &domain, ServiceResolutionCallback callback,
    const std::vector<ServiceType> &preferredTransports,
    const std::optional<std::vector<std::pair<std::string, ServiceType>>> &srvQueries, bool secure,
    std::chrono::steady_clock::time_point deadline)
  {
    // Deliver AT MOST ONCE (double-wrapping when reached via the public entry or
    // performServiceResolutionAsync is harmless) -- tracker 2026-09-25-5 steps-4-8 H-1.
    callback = makeSingleFire(std::move(callback));

    auto actualSrvQueries = buildOrderedSrvQueries(domain, srvQueries, preferredTransports, secure);

    auto result = std::make_shared<ServiceResolutionResult>(domain);

    // Zero-work guard: with no SRV queries to issue, the per-query completion block
    // below never runs, so the user callback would never fire (caller hangs). Mirror
    // the sync path and fall back directly.
    if (actualSrvQueries.empty())
    {
      performFallbackResolutionAsync(domain, result, callback, preferredTransports, {}, secure,
                                     deadline);
      return;
    }

    auto remainingQueries = std::make_shared<std::atomic<std::size_t>>(actualSrvQueries.size());
    // callbackFired ensures the completion callback is invoked exactly once
    auto callbackFired = std::make_shared<std::atomic<bool>>(false);
    // Mutex protects concurrent writes to result->targets AND deniedServices from
    // parallel SRV callbacks.
    auto resultMutex = std::make_shared<std::mutex>();
    // Services whose SRV query returned an RFC 2782 "." abort; the A/AAAA fallback
    // is suppressed per-service (not domain-wide), mirroring the sync path.
    auto deniedServices = std::make_shared<std::vector<ServiceType>>();
    // Async twin of the sync anySrvTransient (tracker 2026-09-30-4 M-4): set when a set exhausts
    // all servers server-local. Written from parallel SRV callbacks, read once in the completer.
    auto anySrvTransient = std::make_shared<std::atomic<bool>>(false);

    auto self = shared_from_this();

    // Shared completer: the last query to decrement to zero runs the join. acq_rel
    // publishes every prior callback's locked writes (targets/deniedServices) to this
    // thread. Invoked from each SRV callback AND from a synchronous issue-throw catch
    // (TS-C1); callbackFired makes it single-fire regardless. The continuation is
    // wrapped so a prelude throw (e.g. bad_alloc) delivers via the callback instead of
    // unwinding into the DNS worker (tracker 2026-09-25-5 TS-M2).
    auto runCompleter = std::make_shared<std::function<void()>>(
      [self, result, remainingQueries, callbackFired, callback, domain, preferredTransports,
       deniedServices, anySrvTransient, secure, deadline]()
      {
        if (remainingQueries->fetch_sub(1, std::memory_order_acq_rel) == 1 &&
            !callbackFired->exchange(true))
        {
          try
          {
            // One shared empty-avenue policy (targets → transient → §4.2 fallback), identical to
            // the NAPTR-S completer so the two cannot drift (tracker 2026-09-30-4 M-4/H-A).
            self->completeSrvJoinAsync(domain, result, callback,
                                       anySrvTransient->load(std::memory_order_acquire),
                                       preferredTransports, *deniedServices, secure, deadline);
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
        auto chain = makeFailoverChain(deadline);

        queryAsyncWithFailover(
          srvQuestion, chain,
          [self, result, service, transportRank, resultMutex, deniedServices, anySrvTransient,
           runCompleter](const DnsResult &srvResult, const std::exception_ptr &srvError)
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
            else if (isTransientError(srvError))
            {
              // All servers exhausted server-local for this set (tracker 2026-09-30-4 M-4).
              anySrvTransient->store(true, std::memory_order_release);
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

  /// SEPARATE once-latches per deadline-MISCONFIGURATION warning (cpp17 round-3 M-1 / sip-voip
  /// LOW-1): a shared latch let a benign sub-budget warning permanently MASK the severe
  /// negative-budget (fail-closed = total outage) warning, or vice-versa. One latch each so the
  /// most severe state is never hidden.
  /// - _negativeDeadlineWarned: a negative budget failed closed (every non-cached resolution ->
  ///   TransientFailure until corrected). The most severe misconfiguration.
  /// - _subBudgetWarned: a positive deadline below one server's UDP-retransmit budget defeats
  ///   RFC 1035 §7.2 next-server failover (per-server sub-budget -> 2026-09-30-5). It ALSO gates the
  ///   one-time sub-budget CHECK: the check runs on each budget>0 resolution UNTIL it fires once,
  ///   so a later smaller override / an updateConfig() shrink is still caught (cpp17 M-2), then the
  ///   cost stops (cpp17 L-2b).
  mutable std::atomic<bool> _negativeDeadlineWarned{false};
  mutable std::atomic<bool> _subBudgetWarned{false};

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
                           const std::vector<ServiceType> &preferredTransports, bool secure,
                           std::chrono::steady_clock::time_point deadline)
  {
    ServiceResolutionResult result(domain);

    // Every NAPTR-failure and no-usable-NAPTR path converges on the same RFC 3263
    // §4.1 direct-SRV fallback, so name it once (review L-f). The deadline (F-2) threads through.
    auto fallbackToDirectSrv = [&]()
    { return performDirectSrvResolutionImpl(domain, preferredTransports, std::nullopt, secure,
                                            deadline); };

    // Step 1: Query NAPTR records
    std::vector<NaptrRecord> naptrRecords;
    try
    {
      DnsResult naptrResult = queryImpl(DnsQuestion(domain, DnsType::NAPTR, DnsClass::IN), deadline);
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
      // Reachable for an unencodable NAPTR query name (encodeName throws before send). Not a
      // server-local fault; fall back to direct SRV (RFC 3263 §4.1).
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

    // Step 3: Query SRV records for 'S' flag targets. Track whether any SRV query exhausted
    // server-local so an empty result carries TransientFailure, not PermanentNoService
    // (steps-4-8 HIGH-A). Also collect the NAPTR-chosen transport set and any RFC 2782 "."
    // suppressions so an all-authoritative failure can fall back to an A/AAAA lookup of the
    // domain on those transports (RFC 3263 §4.2 — tracker 2026-09-30-4 H-3).
    bool anySrvTransient = false;
    std::vector<ServiceType> naptrTransports;
    std::vector<ServiceType> naptrDeniedServices;
    for (const auto &srvTarget : srvTargets)
    {
      // The NAPTR-chosen transport(s), deduped in preference order — the §4.2 fallback set.
      if (std::find(naptrTransports.begin(), naptrTransports.end(), srvTarget.service) ==
          naptrTransports.end())
      {
        naptrTransports.push_back(srvTarget.service);
      }
      try
      {
        DnsResult srvResult =
          queryImpl(DnsQuestion(srvTarget.srvName, DnsType::SRV, DnsClass::IN), deadline);
        if (processSrvRecords(srvResult.srv_records, srvTarget.service, result,
                              srvTarget.naptrPreference))
        {
          naptrDeniedServices.push_back(srvTarget.service);
        }
      }
      catch (const DnsTransientResolutionException &)
      {
        // This SRV set exhausted all servers on server-local conditions (transient). Skip the
        // set (RFC 3263 §4.3) but remember it for the terminal outcome.
        anySrvTransient = true;
        continue;
      }
      catch (const DnsResolverException &)
      {
        // Skip failed SRV queries (authoritative negative), continue with others
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
        // Reachable for an unencodable SRV query name (encodeName throws before send). Not a
        // server-local fault; skip this target, keep the others (RFC 3263 §4.3).
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

    // HIGH-A / MEDIUM-1: capture emptiness BEFORE address resolution, matching the async path
    // (which decides the SRV-transient carry in runCompleter, before resolveTargetAddressesAsync).
    // The SRV step is carried as the terminal avenue ONLY when it produced NO targets at all; if
    // it produced targets that A/AAAA then wiped out, the terminal avenue is the A/AAAA resolution
    // and its outcome stands. Combining a transient SRV sibling with a permanent A/AAAA branch is
    // CROSS-STEP (deferred to tracker 2026-09-30-1); Slice A keeps sync == async here.
    const bool noTargetsBeforeAddr = result.targets.empty();

    if (noTargetsBeforeAddr)
    {
      // M-4/H-3: transient SRV exhaustion -> TransientFailure (no apex fallback); else the RFC 3263
      // §4.2 A/AAAA fallback of the domain on the NAPTR-chosen transport(s), honoring RFC 2782 "."
      // (RFC 3263 §4.2 is the application-defined terminal step; RFC 3403 §8 discourages backing up
      // to OTHER NAPTR rewrite paths, which this is not). Shared with the direct-SRV path. The
      // fallback targets are NOT re-sorted, so they keep NAPTR-preference order and match the async
      // path (tracker 2026-09-30-4 H-3/M-4/H-A).
      resolveEmptySrvAvenue(domain, result, anySrvTransient, naptrTransports, naptrDeniedServices,
                            secure, deadline);
    }
    else
    {
      // Step 4: Resolve hostnames to IP addresses, then sort by priority (and, when secure, discard
      // any non-SIPS-SIP target as belt-and-suspenders). The §4.2 fallback branch above must NOT be
      // sorted here — that would reorder its targets by ServiceType enum and drop NAPTR preference.
      resolveTargetAddresses(result, deadline);
      sortTargetsByPriority(result, secure);
    }

    return result;
  }

  /// \brief Perform SIP resolution asynchronously
  /// \param domain Domain to resolve
  /// \param callback Result callback
  /// \param preferredTransports Preferred transport types
  void performServiceResolutionAsync(const std::string &domain, ServiceResolutionCallback callback,
                                     const std::vector<ServiceType> &preferredTransports,
                                     bool secure, std::chrono::steady_clock::time_point deadline)
  {
    auto self = shared_from_this();

    // Entry-site TS-C1: a synchronous issue throw at the initial NAPTR issue delivers via the
    // callback (uniform deliver-via-callback contract). WITH next-server failover (tracker
    // 2026-09-25-8): NAPTR rotates on SERVFAIL/REFUSED/timeout; a NAPTR NOTIMP/FORMERR is
    // delivered as-is (Q5) so the completer falls straight to direct-SRV without rotating.
    try
    {
      DnsQuestion naptrQuestion(domain, DnsType::NAPTR, DnsClass::IN);
      auto chain = makeFailoverChain(deadline);
      queryAsyncWithFailover(
        naptrQuestion, chain,
        [self, domain, callback, preferredTransports, secure, deadline](
          const DnsResult &naptrResult, const std::exception_ptr &naptrError)
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
              self->performDirectSrvResolutionAsyncImpl(domain, callback, preferredTransports,
                                                        std::nullopt, secure, deadline);
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
              self->performDirectSrvResolutionAsyncImpl(domain, callback, preferredTransports,
                                                        std::nullopt, secure, deadline);
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
              self->resolveTargetAddressesAsync(result, callback, secure, deadline);
              return;
            }

            auto remainingQueries = std::make_shared<std::atomic<std::size_t>>(srvTargets.size());
            // callbackFired ensures the completion callback is invoked exactly once
            auto callbackFired = std::make_shared<std::atomic<bool>>(false);
            // Mutex protects concurrent writes to result->targets from parallel SRV callbacks
            auto resultMutex = std::make_shared<std::mutex>();
            // Per-avenue transient for the NAPTR-S SRV step (steps-4-8 HIGH-A): when every SRV set
            // exhausts server-local, the empty result must be TransientFailure (the §4.2 fallback is
            // suppressed, M-4); when they fail AUTHORITATIVELY, the empty result takes the RFC 3263
            // §4.2 A/AAAA domain fallback below (H-3). Either way the fallback vs transient decision
            // is made in completeSrvJoinAsync, shared with the direct-SRV + sync paths.
            auto anySrvTransient = std::make_shared<std::atomic<bool>>(false);
            // NAPTR-chosen transport set (deduped in preference order) + RFC 2782 "." suppressions,
            // for the H-3 §4.2 A/AAAA fallback when every NAPTR-S SRV set fails authoritatively
            // (tracker 2026-09-30-4 H-3). naptrDenied is written under resultMutex from the SRV
            // callbacks (parity with the direct-SRV async deniedServices).
            std::vector<ServiceType> naptrTransports;
            for (const auto &st : srvTargets)
            {
              if (std::find(naptrTransports.begin(), naptrTransports.end(), st.service) ==
                  naptrTransports.end())
              {
                naptrTransports.push_back(st.service);
              }
            }
            auto naptrDenied = std::make_shared<std::vector<ServiceType>>();

            // Shared completer: last SRV query runs the join; the TS-C1 issue-throw catch
            // reuses it (callbackFired keeps it single-fire); the continuation is wrapped
            // so a prelude throw delivers via the callback, not into the worker (TS-M2).
            auto runCompleter = std::make_shared<std::function<void()>>(
              [self, result, remainingQueries, callbackFired, callback, secure, anySrvTransient,
               domain, naptrTransports, naptrDenied, deadline]()
              {
                if (remainingQueries->fetch_sub(1, std::memory_order_acq_rel) == 1 &&
                    !callbackFired->exchange(true))
                {
                  try
                  {
                    // One shared empty-avenue policy (targets → transient → RFC 3263 §4.2 fallback),
                    // identical to the direct-SRV completer and the sync NAPTR-S path so none can
                    // drift (tracker 2026-09-30-4 M-4/H-3/H-A).
                    self->completeSrvJoinAsync(domain, result, callback,
                                               anySrvTransient->load(std::memory_order_acquire),
                                               naptrTransports, *naptrDenied, secure, deadline);
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
                auto chain = self->makeFailoverChain(deadline);

                self->queryAsyncWithFailover(
                  srvQuestion, chain,
                  [self, result, service, naptrPref, resultMutex, runCompleter, anySrvTransient,
                   naptrDenied](const DnsResult &srvResult, const std::exception_ptr &srvError)
                  {
                    // srvError set (incl. transient exhaustion) -> this SRV set contributed
                    // nothing; the fan-out continues with the other sets.
                    if (!srvError)
                    {
                      try
                      {
                        std::lock_guard<std::mutex> lock(*resultMutex);
                        if (self->processSrvRecords(srvResult.srv_records, service, *result,
                                                    naptrPref))
                        {
                          // RFC 2782 "." -> suppress this service from the H-3 §4.2 fallback.
                          naptrDenied->push_back(service);
                        }
                      }
                      catch (...)
                      {
                        // Ignore individual SRV processing errors
                      }
                    }
                    else if (isTransientError(srvError))
                    {
                      anySrvTransient->store(true, std::memory_order_release);
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

    // RFC 3403 §4.1/§8 (the ORDER field: records MUST be processed lowest ORDER first) + the RFC 3402
    // DDDS algorithm (advance to the next ORDER only when the current tier yields no usable target).
    // Records are already sorted by (order, preference); walk them tier by tier and stop as soon as a
    // completed ORDER tier has produced at least one target. (Note: RFC 3403 §8's "report a failure
    // rather than back up to OTHER rewrite paths" is a DIFFERENT rule from this tier walk — tracker
    // 2026-09-30-4 L-5/L-8.)
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
  /// Positive answers are cached positively; NXDOMAIN, NODATA (NOERROR with no
  /// record of the queried type — including a CNAME-only answer, H-1), are negatively
  /// cached per RFC 2308 — but ONLY when the response carries an SOA record (RFC 2308
  /// §5: a negative response without an SOA SHOULD NOT be cached, as there is no
  /// authoritative TTL to bound it).
  void cacheQueryResult(const DnsQuestion &question, const DnsResult &result)
  {
    if (!_cache)
    {
      return;
    }

    // A truncated response (TC=1) is incomplete and must never be cached — neither its partial
    // answers nor an "absence" it does not actually prove (RFC 2181 §9 — tracker 2026-09-30-4 F-3).
    if (result.header.tc)
    {
      return;
    }

    // isPositiveAnswer, not isSuccess(): a CNAME-only NODATA has ANCOUNT>0 (so isSuccess() is true)
    // but must be cached NEGATIVELY with the SOA-minimum TTL, never positively with the CNAME TTL
    // (tracker 2026-09-30-4 H-1).
    if (isPositiveAnswer(question, result))
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

  /// \brief True if a response carries an NS record in the authority section — the marker of a
  ///        REFERRAL (RFC 2308 §2.2). A NOERROR/empty response with NS-but-no-SOA is a referral
  ///        (server-local: rotate to follow it); one with neither SOA nor NS is a type-3
  ///        authoritative NODATA. Used only by isAuthoritativeNegative (tracker 2026-09-30-4 H-1).
  static bool authorityHasNs(const DnsResult &result)
  {
    for (const auto &rr : result.authority)
    {
      if (rr.type == DnsType::NS)
      {
        return true;
      }
    }
    return false;
  }

  /// \brief A NOERROR answer that carries a CNAME chain but NO record of the queried type is a
  ///        NODATA (RFC 2308 §2.2), NOT a positive result — returning/caching it as success pins an
  ///        empty answer for the (often long) CNAME TTL instead of the SOA-minimum negative TTL
  ///        (tracker 2026-09-30-4 F-7). Generic across qtypes (L-2): a genuinely-chased
  ///        CNAME->target answer keeps a target RR of the queried type in its answer section and is
  ///        correctly still a success.
  static bool isCnameOnlyNodata(const DnsResult &result, DnsType qtype)
  {
    if (result.header.rcode != DnsResponseCode::NOERROR || result.cname_records.empty())
    {
      return false;
    }
    // Meta-qtypes (ANY/AXFR/MAILA/MAILB) never match a concrete answer RR type, so the none_of below
    // would falsely flag a legitimate CNAME answer as NODATA. A CNAME IS the valid answer to an ANY
    // query on an alias (RFC 1034 §3.6.2) — exempt them (tracker 2026-09-30-4 round-3 M-C).
    if (qtype == DnsType::ANY || qtype == DnsType::AXFR || qtype == DnsType::MAILA ||
        qtype == DnsType::MAILB)
    {
      return false;
    }
    // NODATA iff NO answer-section RR matches the queried type (only CNAMEs / other non-qtype RRs).
    return std::none_of(result.answers.begin(), result.answers.end(),
                        [qtype](const DnsResourceRecord &rr) { return rr.type == qtype; });
  }

  /// \brief A usable POSITIVE answer for the queried type: a success that is NOT a CNAME-only
  ///        NODATA. The ONE predicate every success-vs-negative decision uses — the failover gate,
  ///        the cache write, the cache-hit read, and every async delivery — so sync and async can
  ///        never diverge and the answer never depends on cache state (tracker 2026-09-30-4 H-1).
  static bool isPositiveAnswer(const DnsQuestion &question, const DnsResult &result)
  {
    return result.isSuccess() && !isCnameOnlyNodata(result, question.qtype);
  }

  /// \brief Classification of a DELIVERED (no-error) DnsResult, shared by the sync query() leaf and
  ///        the async classifyAsyncCompletion so the two cannot drift (tracker 2026-09-30-4 H-1/M-1).
  enum class DeliveredClass
  {
    Positive,      ///< a usable positive answer -> return/deliver, cache positive.
    Authoritative, ///< an authoritative negative -> STOP rotation, cache-negative (SOA-gated), throw.
    ServerLocal    ///< retryable -> rotate (referral / lame / TC=1 / CNAME-only-without-SOA / error).
  };
  static DeliveredClass classifyDelivered(const DnsQuestion &question, const DnsResult &result)
  {
    if (isPositiveAnswer(question, result))
    {
      return DeliveredClass::Positive;
    }
    // A non-positive truncated (TC=1) response is NEVER evidence of absence (RFC 2181 §9): guard it
    // here — ahead of the CNAME-only and authoritative branches — so NO negative shape (empty,
    // CNAME-only-with-SOA, ...) can be classified authoritative while truncated (tracker
    // 2026-09-30-4 round-3 M-A). isAuthoritativeNegative keeps the same guard as defense-in-depth.
    if (result.header.tc)
    {
      return DeliveredClass::ServerLocal;
    }
    // A CNAME-only NODATA is authoritative ONLY with an SOA: an empty-authority CNAME means the
    // target was not resolved (RFC 1034 §3.6.2), which is not proof of absence -> rotate (M-1).
    if (isCnameOnlyNodata(result, question.qtype))
    {
      return negativeResponseHasSoa(result) ? DeliveredClass::Authoritative
                                            : DeliveredClass::ServerLocal;
    }
    return isAuthoritativeNegative(result) ? DeliveredClass::Authoritative
                                           : DeliveredClass::ServerLocal;
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
  void resolveTargetAddresses(ServiceResolutionResult &result,
                              std::chrono::steady_clock::time_point deadline)
  {
    // Resolve in RFC 2782 PRIORITY order, not DNS wire order (sip-voip HIGH-3): the SRV RRs arrive
    // in whatever cyclic/random rrset order the recursive resolver chose, so without this a slow
    // LOWER-priority (higher-number) backup listed first on the wire could consume the whole
    // deadline and cut a healthy HIGHER-priority target listed later — a priority inversion. Order
    // the resolution by the SAME shared comparator sortTargetsByPriority uses (targetOrderLess:
    // naptrPreference, transport, priority) so the deadline, when it bites, drops the least-preferred
    // targets. The post-loop sortTargetsByPriority still applies RFC 2782 weight ordering among
    // survivors; with the deadline OFF every target is resolved regardless of order, so this is a
    // no-op there. (RFC 2782 WEIGHT ordering within an equal-priority group is NOT applied here — a
    // deadline cutting inside such a group skews the weighted share by wire order; tracked on
    // 2026-09-30-5.)
    std::stable_sort(result.targets.begin(), result.targets.end(), targetOrderLess);

    // Per-avenue outcome (tracker 2026-09-25-8, H4): this is the terminal avenue when SRV/NAPTR
    // produced targets. A target whose A/AAAA exhausted all servers on server-local conditions
    // surfaces from resolveHostname as DnsTransientResolutionException (caught FIRST, before the
    // generic authoritative-negative catch) so an all-transient wipe-out yields TransientFailure,
    // not a permanent no-service.
    bool anyTransient = false;
    for (auto &target : result.targets)
    {
      try
      {
        target.addresses = resolveHostnameImpl(target.hostname, false, deadline);
      }
      catch (const DnsTransientResolutionException &)
      {
        anyTransient = true;
        target.addresses.clear();
      }
      catch (const DnsResolverException &)
      {
        // Authoritative negative / other resolver failure: skip this target.
        target.addresses.clear();
      }
    }

    // Remove targets with no resolved addresses
    result.targets.erase(std::remove_if(result.targets.begin(), result.targets.end(),
                                        [](const ServiceTarget &target)
                                        { return target.addresses.empty(); }),
                         result.targets.end());

    if (!result.targets.empty())
    {
      result.outcome = ResolutionOutcome::Resolved;
    }
    else
    {
      result.outcome = noServiceOutcome(anyTransient);
    }
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

  /// \brief The canonical RFC-2782/3263 target ordering key: (naptrPreference, transport, priority),
  ///        all ascending (lower = more preferred). ONE definition shared by sortTargetsByPriority
  ///        (the final ordering) and resolveTargetAddresses' deadline pre-sort so the two cannot
  ///        drift (cpp17 L-4 / simpl M-1 — a prose "must match" comment was the only prior guard).
  ///        Weight is applied separately by applyWeightedOrdering within each equal-key run.
  static bool targetOrderLess(const ServiceTarget &a, const ServiceTarget &b)
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
  }

  void sortTargetsByPriority(ServiceResolutionResult &result, bool secure = false)
  {
    discardInsecure(result, secure);
    // L-1: the secure belt may have emptied the list AFTER a terminal avenue set outcome=Resolved;
    // an empty result is never a success. A prior non-Resolved outcome (Transient/Permanent) is
    // kept, and the async fan-out recomputes outcome after this call, so it is unaffected.
    if (result.targets.empty() && result.outcome == ResolutionOutcome::Resolved)
    {
      result.outcome = ResolutionOutcome::PermanentNoService;
    }
    std::stable_sort(result.targets.begin(), result.targets.end(), targetOrderLess);

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
                                 const std::vector<ServiceType> &deniedServices, bool secure,
                                 std::chrono::steady_clock::time_point deadline)
  {
    try
    {
      // Transports to build fallback targets for, minus any SRV-"." denied service.
      // When secure, fallbackTransports yields only SIPS transports (TLS/5061 default).
      std::vector<ServiceType> transports =
        fallbackTransports(preferredTransports, deniedServices, secure);
      if (transports.empty())
      {
        // Every candidate transport was declared unavailable (RFC 2782 "."): a permanent
        // no-service for this domain (per-avenue outcome, tracker 2026-09-25-8 H4).
        if (result.targets.empty())
        {
          result.outcome = ResolutionOutcome::PermanentNoService;
        }
        return;
      }

      auto addresses = resolveHostnameImpl(domain, false, deadline);

      appendFallbackTargets(result, domain, transports, addresses);
      result.outcome = ResolutionOutcome::Resolved;
    }
    catch (const DnsTransientResolutionException &)
    {
      // A/AAAA fallback exhausted all servers on server-local conditions -> transient (retryable).
      if (result.targets.empty())
      {
        result.outcome = ResolutionOutcome::TransientFailure;
      }
    }
    catch (const DnsResolverException &)
    {
      // Authoritative negative (no records) / other resolver failure -> permanent no-service.
      if (result.targets.empty())
      {
        result.outcome = ResolutionOutcome::PermanentNoService;
      }
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
                         const std::shared_ptr<std::function<void()>> &finishTarget,
                         const std::shared_ptr<std::vector<char>> &targetTransient,
                         std::chrono::steady_clock::time_point deadline)
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
      auto chain = self->makeFailoverChain(deadline);
      self->queryAsyncWithFailover(
        q, chain, [self, result, targetIndex, hostname, families, famIdx, finishTarget,
                   targetTransient, deadline](const DnsResult &r, const std::exception_ptr &err)
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
            else if (isTransientError(err) && targetIndex < targetTransient->size())
            {
              // This family exhausted all servers on server-local conditions -> mark this
              // target's DISJOINT transient slot (H3). OR across families for the target; only
              // read by the final decrementer, and only significant when the target is wiped out.
              (*targetTransient)[targetIndex] = 1;
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
            self->issueTargetFamily(result, targetIndex, hostname, families, famIdx + 1, finishTarget,
                                    targetTransient, deadline);
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
                           const std::shared_ptr<bool> &anyTransient,
                           std::chrono::steady_clock::time_point deadline)
  {
    // Pre-call statements inside the try so a synchronous PRE-CALL throw yields exactly one
    // finish (TS-C1); the failover helper is no-throw and funnels a synchronous issue-throw into
    // its callback (tracker 2026-09-25-8). This is a single serial chain (one family at a time),
    // so *anyTransient is written without a data race.
    try
    {
      auto self = shared_from_this();
      DnsQuestion q(domain, (*families)[famIdx], DnsClass::IN);
      auto chain = self->makeFailoverChain(deadline);
      self->queryAsyncWithFailover(
        q, chain,
        [self, domain, families, famIdx, addresses, finish, anyTransient, deadline](
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
            self->issueFallbackFamily(domain, families, famIdx + 1, addresses, finish, anyTransient,
                                      deadline);
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
                                      const std::vector<ServiceType> &deniedServices, bool secure,
                                      std::chrono::steady_clock::time_point deadline)
  {
    // Transports to build fallback targets for, minus any SRV-"." denied service.
    // When secure, fallbackTransports yields only SIPS transports (TLS/5061 default),
    // so appendFallbackTargets below never produces a plaintext target — no belt needed.
    // If none remain, there is nothing to resolve — fire the callback immediately.
    auto transportsToUse = fallbackTransports(preferredTransports, deniedServices, secure);
    if (transportsToUse.empty())
    {
      // Every candidate transport declared unavailable (RFC 2782 ".") -> permanent no-service,
      // parity with the sync performFallbackResolution (steps-4-8 M-fallback-denied / MEDIUM-1).
      if (result->targets.empty())
      {
        result->outcome = ResolutionOutcome::PermanentNoService;
      }
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
          result->outcome = noServiceOutcome(*anyTransient);
        }
        callback(*result, nullptr);
      });

    issueFallbackFamily(domain, families, 0, addresses, finish, anyTransient, deadline);
  }

  /// \brief Resolve target addresses asynchronously
  /// \param result Result containing targets to resolve (must be shared_ptr for async safety)
  /// \param callback Result callback
  void resolveTargetAddressesAsync(std::shared_ptr<ServiceResolutionResult> result,
                                   ServiceResolutionCallback callback, bool secure,
                                   std::chrono::steady_clock::time_point deadline)
  {
    if (result->targets.empty())
    {
      // No targets to resolve. Set the terminal outcome unless a prior avenue already set a
      // non-Resolved one (steps-4-8 HIGH-A): the NAPTR-S runCompleter sets TransientFailure here
      // when its SRV step exhausted server-local, and that must survive. A default Resolved with
      // no targets means nothing was found -> PermanentNoService (never a silent Resolved-but-empty).
      if (result->outcome == ResolutionOutcome::Resolved)
      {
        result->outcome = ResolutionOutcome::PermanentNoService;
      }
      callback(*result, nullptr);
      return;
    }

    // remainingTargets starts at N and needs N decrements, so it can only reach 0
    // AFTER every target has been issued -- the completer's erase therefore never
    // races a live per-target index read (tracker 2026-09-25-5 site 1).
    const std::size_t initialTargetCount = result->targets.size();
    auto remainingTargets = std::make_shared<std::atomic<std::size_t>>(initialTargetCount);

    // Per-target transient slots (tracker 2026-09-25-8, H3): DISJOINT one-byte slot per target,
    // written ONLY by that target's own A/AAAA callback (index-disjoint, no shared plain bool /
    // no lock), read ONCE by the single final decrementer. Lets the terminal set the per-avenue
    // outcome: an all-server-local wipe-out of every target yields TransientFailure, not a
    // permanent no-service. The final acq_rel decrement's release-sequence publishes these writes.
    auto targetTransient = std::make_shared<std::vector<char>>(initialTargetCount, 0);

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
      [self, remainingTargets, result, callback, secure, targetTransient]()
      {
        if (remainingTargets->fetch_sub(1, std::memory_order_acq_rel) == 1)
        {
          result->targets.erase(
            std::remove_if(result->targets.begin(), result->targets.end(),
                           [](const ServiceTarget &t) { return t.addresses.empty(); }),
            result->targets.end());
          self->sortTargetsByPriority(*result, secure);
          // Per-avenue outcome (H3): if every target was wiped out, distinguish a transient
          // (any target hit server-local exhaustion) from a permanent no-service. Reading the
          // disjoint slots here is single-threaded (only the last decrement enters this block).
          if (!result->targets.empty())
          {
            result->outcome = ResolutionOutcome::Resolved;
          }
          else
          {
            const bool anyTransient =
              std::any_of(targetTransient->begin(), targetTransient->end(),
                          [](char c) { return c != 0; });
            result->outcome = noServiceOutcome(anyTransient);
          }
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
        issueTargetFamily(result, targetIndex, hostname, families, 0, finishTarget, targetTransient,
                          deadline);
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