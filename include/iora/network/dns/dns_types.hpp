// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <optional>
#include <algorithm>
#include <cctype>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief DNS message opcodes (RFC 1035)
enum class DnsOpcode : std::uint8_t
{
  Query = 0,        ///< Standard query
  IQuery = 1,       ///< Inverse query (obsolete)
  Status = 2,       ///< Server status request
  Notify = 4,       ///< Zone change notification (RFC 1996)
  Update = 5        ///< Dynamic update (RFC 2136)
};

/// \brief DNS response codes (RFC 1035, RFC 2136, RFC 6895)
enum class DnsResponseCode : std::uint8_t
{
  NOERROR = 0,      ///< No error
  FORMERR = 1,      ///< Format error
  SERVFAIL = 2,     ///< Server failure
  NXDOMAIN = 3,     ///< Name does not exist
  NOTIMP = 4,       ///< Not implemented
  REFUSED = 5,      ///< Query refused
  YXDOMAIN = 6,     ///< Name exists when it should not
  YXRRSET = 7,      ///< RR set exists when it should not
  NXRRSET = 8,      ///< RR set that should exist does not
  NOTAUTH = 9,      ///< Not authorized
  NOTZONE = 10,     ///< Name not contained in zone
  BADVERS = 16      ///< Bad OPT version (RFC 6891)
};

/// \brief DNS record types (RFC 1035 and extensions, SIP-focused)
enum class DnsType : std::uint16_t
{
  // Basic types
  A = 1,            ///< IPv4 address
  NS = 2,           ///< Name server
  CNAME = 5,        ///< Canonical name
  SOA = 6,          ///< Start of authority
  PTR = 12,         ///< Pointer record
  MX = 15,          ///< Mail exchange
  TXT = 16,         ///< Text record
  AAAA = 28,        ///< IPv6 address

  // SIP-critical record types (first-class citizens)
  SRV = 33,         ///< Service location (RFC 2052, critical for SIP)
  NAPTR = 35,       ///< Naming Authority Pointer (RFC 3403, essential for SIP)

  // Query types
  AXFR = 252,       ///< Zone transfer
  MAILB = 253,      ///< Mail box records
  MAILA = 254,      ///< Mail agent records
  ANY = 255         ///< All records
};

/// \brief DNS record class (RFC 1035)
enum class DnsClass : std::uint16_t
{
  IN = 1,           ///< Internet class
  CS = 2,           ///< CSNET class (obsolete)
  CH = 3,           ///< CHAOS class
  HS = 4,           ///< Hesiod class
  ANY = 255         ///< Any class
};

/// \brief DNS message flags and header structure
struct DnsHeader
{
  std::uint16_t id;                 ///< Query identifier
  bool qr;                          ///< Query/Response flag
  DnsOpcode opcode;                 ///< Operation code
  bool aa;                          ///< Authoritative answer
  bool tc;                          ///< Truncation flag
  bool rd;                          ///< Recursion desired
  bool ra;                          ///< Recursion available
  std::uint8_t z;                   ///< Reserved for future use (must be zero)
  DnsResponseCode rcode;            ///< Response code
  std::uint16_t qdcount;            ///< Question count
  std::uint16_t ancount;            ///< Answer count
  std::uint16_t nscount;            ///< Authority count
  std::uint16_t arcount;            ///< Additional count

  /// \brief Default constructor
  DnsHeader()
    : id(0), qr(false), opcode(DnsOpcode::Query), aa(false), tc(false),
      rd(true), ra(false), z(0), rcode(DnsResponseCode::NOERROR),
      qdcount(0), ancount(0), nscount(0), arcount(0)
  {
  }
};

/// \brief DNS question section
struct DnsQuestion
{
  std::string qname;                ///< Domain name
  DnsType qtype;                    ///< Query type
  DnsClass qclass;                  ///< Query class

  /// \brief Constructor
  DnsQuestion(const std::string& name = "", DnsType type = DnsType::A, 
              DnsClass cls = DnsClass::IN)
    : qname(name), qtype(type), qclass(cls)
  {
  }
};

/// \brief Cache key for DNS queries (hashable and comparable)
struct DnsCacheKey
{
  std::string qname;                ///< Domain name (case-insensitive)
  DnsType qtype;                    ///< Query type
  DnsClass qclass;                  ///< Query class

  /// \brief Create cache key from DNS question
  static DnsCacheKey fromQuestion(const DnsQuestion& question)
  {
    DnsCacheKey key;
    // Convert to lowercase for case-insensitive comparison
    key.qname = question.qname;
    std::transform(key.qname.begin(), key.qname.end(), key.qname.begin(), ::tolower);
    key.qtype = question.qtype;
    key.qclass = question.qclass;
    return key;
  }

  /// \brief Equality operator for cache lookup
  bool operator==(const DnsCacheKey& other) const
  {
    return qname == other.qname && qtype == other.qtype && qclass == other.qclass;
  }

  /// \brief Less-than operator for ordered containers
  bool operator<(const DnsCacheKey& other) const
  {
    if (qname != other.qname) return qname < other.qname;
    if (qtype != other.qtype) return static_cast<uint16_t>(qtype) < static_cast<uint16_t>(other.qtype);
    return static_cast<uint16_t>(qclass) < static_cast<uint16_t>(other.qclass);
  }
};

} // namespace dns
} // namespace network  
} // namespace iora

// Hash specialization for DnsCacheKey to work with std::unordered_map
namespace std
{
template<>
struct hash<iora::network::dns::DnsCacheKey>
{
  std::size_t operator()(const iora::network::dns::DnsCacheKey& key) const
  {
    std::size_t h1 = std::hash<std::string>{}(key.qname);
    std::size_t h2 = std::hash<std::uint16_t>{}(static_cast<std::uint16_t>(key.qtype));
    std::size_t h3 = std::hash<std::uint16_t>{}(static_cast<std::uint16_t>(key.qclass));
    return h1 ^ (h2 << 1) ^ (h3 << 2);
  }
};
}

namespace iora {
namespace network {
namespace dns {

/// \brief Base DNS resource record
struct DnsResourceRecord
{
  std::string name;                 ///< Domain name
  DnsType type;                     ///< Record type
  DnsClass cls;                     ///< Record class
  std::uint32_t ttl;                ///< Time to live (seconds)
  std::uint16_t rdlength;           ///< Resource data length
  std::vector<std::uint8_t> rdata;  ///< Resource data (raw)

  /// \brief Constructor
  DnsResourceRecord(const std::string& n = "", DnsType t = DnsType::A,
                    DnsClass c = DnsClass::IN, std::uint32_t ttl_val = 0)
    : name(n), type(t), cls(c), ttl(ttl_val), rdlength(0)
  {
  }

  /// \brief Get expiration time based on TTL
  std::chrono::steady_clock::time_point getExpirationTime() const
  {
    return std::chrono::steady_clock::now() + std::chrono::seconds(ttl);
  }

  /// \brief Check if record has expired
  bool hasExpired() const
  {
    return std::chrono::steady_clock::now() >= getExpirationTime();
  }
};

/// \brief SRV record structure (RFC 2052) - Critical for SIP
struct SrvRecord : public DnsResourceRecord
{
  std::uint16_t priority;           ///< Priority (lower = higher priority)
  std::uint16_t weight;             ///< Weight for load balancing
  std::uint16_t port;               ///< Service port
  std::string target;               ///< Target hostname

  /// \brief Constructor
  SrvRecord(const std::string& name = "", std::uint16_t prio = 0,
            std::uint16_t w = 0, std::uint16_t p = 0, 
            const std::string& tgt = "", std::uint32_t ttl_val = 0)
    : DnsResourceRecord(name, DnsType::SRV, DnsClass::IN, ttl_val),
      priority(prio), weight(w), port(p), target(tgt)
  {
  }
};

/// \brief NAPTR record structure (RFC 3403) - Essential for SIP
struct NaptrRecord : public DnsResourceRecord
{
  std::uint16_t order;              ///< Order of processing
  std::uint16_t preference;         ///< Preference within same order
  std::string flags;                ///< Control flags (e.g., "S", "A", "U")
  std::string service;              ///< Service type (e.g., "SIP+D2U")
  std::string regexp;               ///< Regular expression for transformation
  std::string replacement;          ///< Replacement domain name

  /// \brief Constructor
  NaptrRecord(const std::string& name = "", std::uint16_t ord = 0,
              std::uint16_t pref = 0, const std::string& f = "",
              const std::string& s = "", const std::string& re = "",
              const std::string& repl = "", std::uint32_t ttl_val = 0)
    : DnsResourceRecord(name, DnsType::NAPTR, DnsClass::IN, ttl_val),
      order(ord), preference(pref), flags(f), service(s), 
      regexp(re), replacement(repl)
  {
  }
};

/// \brief A record structure (IPv4 address)
struct ARecord : public DnsResourceRecord
{
  std::string address;              ///< IPv4 address string

  /// \brief Constructor
  ARecord(const std::string& name = "", const std::string& addr = "",
          std::uint32_t ttl_val = 0)
    : DnsResourceRecord(name, DnsType::A, DnsClass::IN, ttl_val),
      address(addr)
  {
  }
};

/// \brief AAAA record structure (IPv6 address)  
struct AAAARecord : public DnsResourceRecord
{
  std::string address;              ///< IPv6 address string

  /// \brief Constructor
  AAAARecord(const std::string& name = "", const std::string& addr = "",
             std::uint32_t ttl_val = 0)
    : DnsResourceRecord(name, DnsType::AAAA, DnsClass::IN, ttl_val),
      address(addr)
  {
  }
};

/// \brief CNAME record structure
struct CnameRecord : public DnsResourceRecord
{
  std::string cname;                ///< Canonical name

  /// \brief Constructor
  CnameRecord(const std::string& name = "", const std::string& cn = "",
              std::uint32_t ttl_val = 0)
    : DnsResourceRecord(name, DnsType::CNAME, DnsClass::IN, ttl_val),
      cname(cn)
  {
  }
};

/// \brief MX record structure
struct MxRecord : public DnsResourceRecord
{
  std::uint16_t preference;         ///< Mail server preference
  std::string exchange;             ///< Mail server hostname

  /// \brief Constructor
  MxRecord(const std::string& name = "", std::uint16_t pref = 0,
           const std::string& exch = "", std::uint32_t ttl_val = 0)
    : DnsResourceRecord(name, DnsType::MX, DnsClass::IN, ttl_val),
      preference(pref), exchange(exch)
  {
  }
};

/// \brief TXT record structure
struct TxtRecord : public DnsResourceRecord
{
  std::vector<std::string> text;    ///< Text strings

  /// \brief Constructor
  TxtRecord(const std::string& name = "", 
            const std::vector<std::string>& txt = {},
            std::uint32_t ttl_val = 0)
    : DnsResourceRecord(name, DnsType::TXT, DnsClass::IN, ttl_val),
      text(txt)
  {
  }
};

/// \brief PTR record structure (reverse DNS)
struct PtrRecord : public DnsResourceRecord
{
  std::string ptrdname;             ///< Pointer domain name

  /// \brief Constructor
  PtrRecord(const std::string& name = "", const std::string& ptr = "",
            std::uint32_t ttl_val = 0)
    : DnsResourceRecord(name, DnsType::PTR, DnsClass::IN, ttl_val),
      ptrdname(ptr)
  {
  }
};

/// \brief SOA record structure (Start of Authority, RFC 1035)
struct SoaRecord : public DnsResourceRecord
{
  std::string mname;                ///< Primary nameserver
  std::string rname;                ///< Responsible person email
  std::uint32_t serial;             ///< Serial number
  std::uint32_t refresh;            ///< Refresh interval (seconds)
  std::uint32_t retry;              ///< Retry interval (seconds) 
  std::uint32_t expire;             ///< Expire time (seconds)
  std::uint32_t minimum;            ///< Minimum TTL for negative caching (RFC 2308)

  /// \brief Constructor
  SoaRecord(const std::string& name = "", const std::string& primary = "",
            const std::string& email = "", std::uint32_t ser = 0,
            std::uint32_t ref = 0, std::uint32_t ret = 0, 
            std::uint32_t exp = 0, std::uint32_t min = 0, 
            std::uint32_t ttl_val = 0)
    : DnsResourceRecord(name, DnsType::SOA, DnsClass::IN, ttl_val),
      mname(primary), rname(email), serial(ser), refresh(ref), 
      retry(ret), expire(exp), minimum(min)
  {
  }
};

/// \brief DNS query result container
struct DnsResult
{
  DnsHeader header;                 ///< Response header
  std::vector<DnsQuestion> questions; ///< Question section
  std::vector<DnsResourceRecord> answers; ///< Answer section
  std::vector<DnsResourceRecord> authority; ///< Authority section
  std::vector<DnsResourceRecord> additional; ///< Additional section
  
  // Parsed typed records for convenience (SIP-focused)
  std::vector<ARecord> a_records;
  std::vector<AAAARecord> aaaa_records;
  std::vector<SrvRecord> srv_records;       ///< Critical for SIP
  std::vector<NaptrRecord> naptr_records;   ///< Essential for SIP
  std::vector<CnameRecord> cname_records;
  std::vector<MxRecord> mx_records;
  std::vector<TxtRecord> txt_records;
  std::vector<PtrRecord> ptr_records;
  std::vector<SoaRecord> soa_records;       ///< SOA records (for negative caching)

  /// \brief Check if response indicates success
  bool isSuccess() const
  {
    return header.rcode == DnsResponseCode::NOERROR && 
           header.ancount > 0;
  }

  /// \brief Check if response was truncated (needs TCP retry)
  bool isTruncated() const
  {
    return header.tc;
  }

  /// \brief Get human-readable response code string
  std::string getResponseCodeString() const
  {
    switch (header.rcode)
    {
      case DnsResponseCode::NOERROR:
        return "NOERROR";
      case DnsResponseCode::FORMERR:
        return "FORMERR";
      case DnsResponseCode::SERVFAIL:
        return "SERVFAIL";
      case DnsResponseCode::NXDOMAIN:
        return "NXDOMAIN";
      case DnsResponseCode::NOTIMP:
        return "NOTIMP";
      case DnsResponseCode::REFUSED:
        return "REFUSED";
      case DnsResponseCode::YXDOMAIN:
        return "YXDOMAIN";
      case DnsResponseCode::YXRRSET:
        return "YXRRSET";
      case DnsResponseCode::NXRRSET:
        return "NXRRSET";
      case DnsResponseCode::NOTAUTH:
        return "NOTAUTH";
      case DnsResponseCode::NOTZONE:
        return "NOTZONE";
      case DnsResponseCode::BADVERS:
        return "BADVERS";
      default:
        return "UNKNOWN(" + std::to_string(static_cast<uint8_t>(header.rcode)) + ")";
    }
  }
};

/// \brief DNS transport mode
enum class DnsTransportMode
{
  UDP,              ///< UDP transport (primary)
  TCP,              ///< TCP transport (fallback)
  Both              ///< Try UDP first, fallback to TCP
};

/// \brief DNS client configuration with comprehensive timeout and retry settings
/// 
/// This structure configures all aspects of DNS client behavior including timeouts,
/// retry policies, caching, and transport selection. All timeout values use
/// std::chrono types for type safety and clarity.
struct DnsConfig
{
  // =============================================================================
  // Server Configuration
  // =============================================================================
  
  /// \brief DNS servers to query (IPv4 addresses)
  /// Default: Google DNS (8.8.8.8) and Cloudflare DNS (1.1.1.1)
  std::vector<std::string> servers{"8.8.8.8", "1.1.1.1"};
  
  /// \brief DNS server port
  /// Default: 53 (standard DNS port)
  std::uint16_t port{53};
  
  // =============================================================================
  // Timeout Configuration (with clear units and defaults)
  // =============================================================================
  
  /// \brief Initial query timeout before first retry
  /// Default: 5000ms (5 seconds)
  /// Range: 1000ms - 30000ms recommended
  /// Used for: UDP/TCP query response timeout
  std::chrono::milliseconds timeout{5000};
  
  /// \brief TCP-specific connection and query timeout
  /// Default: 10000ms (10 seconds) 
  /// Range: 5000ms - 60000ms recommended
  /// Used for: TCP connection establishment + query response
  /// Note: Should be >= timeout since TCP requires connection setup
  std::chrono::milliseconds tcpTimeout{10000};
  
  /// \brief Cache entry time-to-live override
  /// Default: 300s (5 minutes)
  /// Range: 60s - 86400s recommended
  /// Used for: Maximum cache retention time (actual TTL from DNS records may be shorter)
  std::chrono::seconds cacheTimeout{300};
  
  // =============================================================================
  // Retry Policy Configuration (exponential backoff with jitter)
  // =============================================================================
  
  /// \brief Maximum number of retry attempts per query
  /// Default: 3 retries (total 4 attempts including initial)
  /// Range: 0-10 recommended
  int retryCount{3};
  
  /// \brief Initial delay before first retry
  /// Default: 500ms
  /// Range: 100ms - 5000ms recommended
  /// Note: Subsequent delays use exponential backoff (delay *= retryMultiplier)
  std::chrono::milliseconds initialRetryDelay{500};
  
  /// \brief Exponential backoff multiplier for retry delays
  /// Default: 2.0 (double delay each retry)
  /// Range: 1.1 - 3.0 recommended
  /// Examples: 
  ///   2.0 → delays: 500ms, 1000ms, 2000ms, 4000ms
  ///   1.5 → delays: 500ms, 750ms, 1125ms, 1687ms
  double retryMultiplier{2.0};
  
  /// \brief Maximum retry delay cap
  /// Default: 10000ms (10 seconds)
  /// Range: 1000ms - 30000ms recommended
  /// Note: Prevents exponential backoff from becoming too large
  std::chrono::milliseconds maxRetryDelay{10000};
  
  /// \brief Jitter factor to randomize retry delays (prevents thundering herd)
  /// Default: 0.1 (±10% randomization)
  /// Range: 0.0 (no jitter) - 0.5 (±50% jitter) recommended
  /// Formula: actual_delay = base_delay * (1.0 ± jitterFactor)
  double jitterFactor{0.1};
  
  // =============================================================================
  // Caching Configuration
  // =============================================================================
  
  /// \brief Enable DNS result caching
  /// Default: true
  bool enableCache{true};
  
  /// \brief Maximum cache entries (ignored - ExpiringCache uses time-based expiration)
  /// Default: 10000 (kept for API compatibility)
  /// Note: Actual cache size limited by TTL expiration, not entry count
  std::size_t maxCacheSize{10000};
  
  // =============================================================================
  // Transport Configuration
  // =============================================================================
  
  /// \brief Transport mode preference
  /// Default: Both (UDP with TCP fallback on truncation)
  /// Options: UDP_Only, TCP_Only, Both
  DnsTransportMode transportMode{DnsTransportMode::Both};
  
  /// \brief Request recursion from DNS server (RD flag)
  /// Default: true (most common for client queries)
  bool recursionDesired{true};
  
  /// \brief Maximum UDP message size before TCP fallback
  /// Default: 512 bytes (RFC 1035 minimum)
  /// Range: 512 - 4096 bytes
  /// Note: Larger values may cause fragmentation issues
  std::size_t maxUdpSize{512};
  
  /// \brief Maximum TCP receive buffer size per session
  /// Default: 65536 bytes (64KB per session)
  /// Range: 8192 - 1048576 bytes (8KB - 1MB)
  /// Note: Prevents unbounded memory usage under high load or attacks.
  /// Sessions exceeding this limit will be closed to prevent DoS.
  std::size_t maxTcpBufferSize{65536};
  
  /// \brief Default constructor
  DnsConfig() = default;
};

/// \brief DNS protocol constants
namespace constants
{
  constexpr std::uint16_t DNS_PORT = 53;
  constexpr std::size_t DNS_HEADER_SIZE = 12;
  constexpr std::size_t DNS_MAX_UDP_SIZE = 512;
  constexpr std::size_t DNS_MAX_TCP_SIZE = 65535;
  constexpr std::size_t DNS_MAX_LABEL_SIZE = 63;
  constexpr std::size_t DNS_MAX_NAME_SIZE = 253;
  constexpr std::uint8_t DNS_COMPRESSION_MASK = 0xC0;
  constexpr std::uint16_t DNS_COMPRESSION_POINTER_MASK = 0x3FFF;
}

} // namespace dns
} // namespace network
} // namespace iora