// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include "dns_types.hpp"
#include "iora/util/expiring_cache.hpp"
#include <memory>
#include <chrono>
#include <functional>
#include <atomic>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief Cache statistics for monitoring
struct DnsCacheStats
{
  std::uint64_t hits{0};                        ///< Cache hits
  std::uint64_t misses{0};                      ///< Cache misses
  std::uint64_t negative_hits{0};               ///< Negative cache hits
  std::uint64_t insertions{0};                  ///< New cache insertions (not replacements)
  std::uint64_t replacements{0};                ///< Cache entry replacements
  std::uint64_t negative_insertions{0};         ///< New negative cache insertions
  std::uint64_t negative_replacements{0};       ///< Negative cache entry replacements
  std::uint64_t current_entries{0};             ///< Accurate current entry count
  std::uint64_t current_negative_entries{0};    ///< Accurate current negative entries
  std::chrono::steady_clock::time_point last_cleanup; ///< Last cleanup time

  /// \brief Calculate hit ratio
  double getHitRatio() const
  {
    auto total = hits + misses + negative_hits;
    return total > 0 ? static_cast<double>(hits + negative_hits) / total : 0.0;
  }
};

/// \brief DNS cache result wrapper for positive and negative caching
struct CachedDnsResult
{
  DnsResult result;
  bool isNegative{false};
  std::string errorMessage;
  
  CachedDnsResult() = default;
  
  // Positive result constructor
  explicit CachedDnsResult(const DnsResult& res) 
    : result(res), isNegative(false) {}
  
  // Negative result constructor  
  CachedDnsResult(const DnsResult& res, const std::string& error)
    : result(res), isNegative(true), errorMessage(error) {}
};

/// \brief Thread-safe DNS cache with TTL-aware expiration
/// 
/// This cache uses Iora's ExpiringCache for robust TTL handling and automatic cleanup.
/// It supports both positive and negative response caching per RFC 2308.
class DnsCache
{
public:
  /// \brief Constructor with default configuration
  DnsCache() : defaultTtl_(std::chrono::seconds(300)) 
  { 
    initializeCache();
  } // 5 minute default TTL
  
  /// \brief Constructor with configurable TTL
  /// \param ttl Time-to-live for cache entries
  explicit DnsCache(std::chrono::seconds ttl) : defaultTtl_(ttl) 
  {
    initializeCache();
  }
  
  /// \brief Constructor with maximum cache size (ignored - ExpiringCache uses TTL only)
  /// \param maxSize Ignored for compatibility with old API  
  explicit DnsCache(std::size_t maxSize) : defaultTtl_(std::chrono::seconds(300))
  {
    // maxSize is ignored - ExpiringCache uses time-based expiration only
    initializeCache();
  }

  /// \brief Store DNS query result in cache with minimum TTL
  /// 
  /// This implementation uses a single TTL for the entire DNS result, calculated as the
  /// minimum TTL across all resource records in the response. This follows the conservative
  /// approach from RFC 1035 and ensures correctness when records have different expiration times.
  /// 
  /// \note Future Enhancement: Per-record caching granularity could be implemented by
  ///       storing individual records with their respective TTLs. This would require:
  ///       - Separate cache keys per record type (e.g., "example.com:A", "example.com:AAAA")
  ///       - Modified cache lookup to merge available records into a response
  ///       - Handling of partial cache hits (some record types expired, others valid)
  ///       - More complex statistics tracking for per-record hit/miss ratios
  /// 
  /// \param question DNS question used as cache key
  /// \param result DNS query result to cache
  void put(const DnsQuestion& question, const DnsResult& result)
  {
    DnsCacheKey key = DnsCacheKey::fromQuestion(question);
    
    // Check what type of entry exists to handle counter correctly
    auto existingEntry = cache_->get(key);
    bool hadEntry = existingEntry.has_value();
    bool hadNegativeEntry = hadEntry && existingEntry->isNegative;
    
    // Calculate TTL from DNS result
    std::uint32_t ttl = calculateResultTtl(result);
    
    // Store positive result
    CachedDnsResult cachedResult(result);
    cache_->set(key, cachedResult, std::chrono::seconds(ttl));
    
    // Update statistics - distinguish insertions from replacements
    if (!hadEntry)
    {
      // New entry
      stats_.insertions.fetch_add(1);
      stats_.current_entries.fetch_add(1);
    }
    else if (hadNegativeEntry)
    {
      // Replacing negative entry with positive entry
      stats_.replacements.fetch_add(1);
      stats_.current_negative_entries.fetch_sub(1);
      stats_.current_entries.fetch_add(1);
    }
    else
    {
      // Replacing positive with positive
      stats_.replacements.fetch_add(1);
      // No current_entries change needed
    }
  }

  /// \brief Store negative DNS response in cache (RFC 2308)
  /// \param question DNS question used as cache key  
  /// \param result DNS error result to cache
  /// \param negativeTtl TTL for negative caching (from SOA or default)
  /// \param errorMessage Error description
  void putNegative(const DnsQuestion& question, const DnsResult& result, 
                   std::uint32_t negativeTtl, const std::string& errorMessage)
  {
    DnsCacheKey key = DnsCacheKey::fromQuestion(question);
    
    // Check what type of entry exists to handle counter correctly
    auto existingEntry = cache_->get(key);
    bool hadEntry = existingEntry.has_value();
    bool hadNegativeEntry = hadEntry && existingEntry->isNegative;
    
    // Store negative result
    CachedDnsResult cachedResult(result, errorMessage);
    cache_->set(key, cachedResult, std::chrono::seconds(negativeTtl));
    
    // Update statistics - distinguish insertions from replacements
    if (!hadEntry)
    {
      // New entry
      stats_.negative_insertions.fetch_add(1);
      stats_.current_negative_entries.fetch_add(1);
    }
    else if (!hadNegativeEntry)
    {
      // Replacing positive entry with negative entry
      stats_.negative_replacements.fetch_add(1);
      stats_.current_entries.fetch_sub(1);
      stats_.current_negative_entries.fetch_add(1);
    }
    else
    {
      // Replacing negative with negative
      stats_.negative_replacements.fetch_add(1);
      // No current counter change needed
    }
  }

  /// \brief Store negative DNS response with automatic SOA TTL calculation (RFC 2308)
  /// \param question DNS question used as cache key  
  /// \param result DNS error result to cache (should contain SOA in authority section)
  /// \param errorMessage Error description
  void putNegative(const DnsQuestion& question, const DnsResult& result, 
                   const std::string& errorMessage)
  {
    std::uint32_t negativeTtl = calculateNegativeTtl(result);
    putNegative(question, result, negativeTtl, errorMessage);
  }

  /// \brief Retrieve cached DNS result
  /// \param question DNS question to look up
  /// \param result Output parameter for cached result
  /// \return true if cache hit, false if miss or expired
  bool get(const DnsQuestion& question, DnsResult& result)
  {
    DnsCacheKey key = DnsCacheKey::fromQuestion(question);
    
    auto cachedResult = cache_->get(key);
    if (!cachedResult.has_value())
    {
      stats_.misses.fetch_add(1);
      return false;
    }
    
    // Return the cached result
    result = cachedResult->result;
    
    if (cachedResult->isNegative)
    {
      stats_.negative_hits.fetch_add(1);
    }
    else
    {
      stats_.hits.fetch_add(1);
    }
    
    return true;
  }

  /// \brief Remove specific entry from cache
  /// \param question DNS question to remove
  void remove(const DnsQuestion& question)
  {
    DnsCacheKey key = DnsCacheKey::fromQuestion(question);
    cache_->remove(key);
  }

  /// \brief Clear entire cache (preserves historical statistics)
  /// 
  /// This method clears all cached entries and resets current entry counters,
  /// but preserves historical statistics (hits, misses, insertions) for monitoring.
  /// The cleanupCallback is preserved and will continue to function correctly.
  /// 
  /// \note For full statistics reset, use clear(true)
  void clear()
  {
    clear(false); // Default: preserve historical statistics
  }
  
  /// \brief Clear entire cache with optional statistics reset
  /// 
  /// This method clears all cached entries and resets current entry counters.
  /// The cleanupCallback is preserved and will continue to function correctly
  /// after reinitializing the ExpiringCache with the same TTL and callback.
  /// 
  /// \param resetHistoricalStats If true, reset all statistics including historical counters
  ///                            If false, preserve hits/misses/insertions for monitoring
  void clear(bool resetHistoricalStats)
  {
    // Reset current entry counters (always)
    stats_.current_entries.store(0);
    stats_.current_negative_entries.store(0);
    
    // Reset historical statistics if requested
    if (resetHistoricalStats)
    {
      stats_.hits.store(0);
      stats_.misses.store(0);
      stats_.negative_hits.store(0);
      stats_.insertions.store(0);
      stats_.replacements.store(0);
      stats_.negative_insertions.store(0);
      stats_.negative_replacements.store(0);
    }
    
    // ExpiringCache doesn't have a clear method, so we create a new instance
    // The cleanupCallback_ is preserved and passed to initializeCache()
    // The defaultTtl_ is also preserved from construction time
    initializeCache();
  }

  /// \brief Get current cache statistics
  /// \return Cache statistics with accurate current entry counts
  DnsCacheStats getStats() const
  {
    DnsCacheStats currentStats;
    currentStats.hits = stats_.hits.load();
    currentStats.misses = stats_.misses.load();
    currentStats.negative_hits = stats_.negative_hits.load();
    currentStats.insertions = stats_.insertions.load();
    currentStats.replacements = stats_.replacements.load();
    currentStats.negative_insertions = stats_.negative_insertions.load();
    currentStats.negative_replacements = stats_.negative_replacements.load();
    
    // Use accurate counters maintained via eviction callbacks
    currentStats.current_entries = stats_.current_entries.load();
    currentStats.current_negative_entries = stats_.current_negative_entries.load();
    
    currentStats.last_cleanup = std::chrono::steady_clock::now();
    return currentStats;
  }

  /// \brief Force cleanup of expired entries (no-op - ExpiringCache handles this)
  /// \return Always returns 0 since ExpiringCache manages cleanup automatically
  std::size_t cleanupExpired()
  {
    // ExpiringCache handles cleanup automatically every 5 seconds
    return 0;
  }

  /// \brief Set cleanup callback (no-op for compatibility)
  /// \param callback Cleanup callback function
  void setCleanupCallback(std::function<void(const DnsCacheStats&)> callback)
  {
    // Store callback for potential future use
    cleanupCallback_ = callback;
  }

private:
  /// \brief Underlying expiring cache
  std::unique_ptr<util::ExpiringCache<DnsCacheKey, CachedDnsResult>> cache_;
  
  /// \brief Default TTL for cache entries
  std::chrono::seconds defaultTtl_;
  
  /// \brief Atomic statistics counters
  struct AtomicStats
  {
    std::atomic<std::uint64_t> hits{0};
    std::atomic<std::uint64_t> misses{0}; 
    std::atomic<std::uint64_t> negative_hits{0};
    std::atomic<std::uint64_t> insertions{0};
    std::atomic<std::uint64_t> replacements{0};
    std::atomic<std::uint64_t> negative_insertions{0};
    std::atomic<std::uint64_t> negative_replacements{0};
    std::atomic<std::uint64_t> current_entries{0};          ///< Accurate current positive entries
    std::atomic<std::uint64_t> current_negative_entries{0}; ///< Accurate current negative entries
  } stats_;
  
  /// \brief Optional cleanup callback
  std::function<void(const DnsCacheStats&)> cleanupCallback_;

  /// \brief Initialize cache with eviction callback
  void initializeCache()
  {
    auto evictionCallback = [this](const DnsCacheKey& key, const CachedDnsResult& result)
    {
      // Decrement appropriate counter when entries are evicted
      if (result.isNegative)
      {
        stats_.current_negative_entries.fetch_sub(1);
      }
      else
      {
        stats_.current_entries.fetch_sub(1);
      }
    };
    
    cache_ = std::make_unique<util::ExpiringCache<DnsCacheKey, CachedDnsResult>>(defaultTtl_, evictionCallback);
  }

  /// \brief Calculate negative TTL from SOA records (RFC 2308)
  /// 
  /// This method implements RFC 2308 negative caching TTL calculation with multiple fallback levels:
  /// 
  /// 1. **Preferred**: Uses parsed SOA records from result.soa_records
  ///    - Extracts the SOA MINIMUM field (proper RFC 2308 behavior)
  ///    - Returns min(SOA.minimum, SOA.ttl) to respect both limits
  /// 
  /// 2. **Fallback**: Scans result.authority for unparsed SOA records
  ///    - Uses SOA record TTL as approximation (less precise than MINIMUM field)
  ///    - This handles cases where SOA parsing might have been missed
  ///    - Note: This is less accurate as it doesn't extract MINIMUM from RDATA
  /// 
  /// 3. **Default**: Uses provided default when no SOA found
  ///    - Standard fallback per RFC 2308 recommendations
  /// 
  /// The authority section fallback exists because SOA records in NXDOMAIN responses
  /// typically appear in the authority section, and our SOA parsing should have moved
  /// them to soa_records. If this fallback is frequently used, it may indicate a parsing issue.
  ///
  /// \param result DNS query result containing potential SOA records  
  /// \param defaultNegativeTtl Fallback TTL if no SOA found (default: 5 minutes)
  /// \return Negative TTL in seconds (from SOA minimum or default)
  std::uint32_t calculateNegativeTtl(const DnsResult& result, std::uint32_t defaultNegativeTtl = 300) const
  {
    // RFC 2308: Use SOA MINIMUM field for negative caching (preferred path)
    for (const auto& record : result.soa_records)
    {
      return std::min(record.minimum, record.ttl); // Use minimum of SOA minimum and TTL
    }
    
    // Fallback: check authority section for SOA records that weren't parsed into soa_records
    // This should be rare if SOA parsing is working correctly
    for (const auto& record : result.authority)
    {
      if (record.type == DnsType::SOA)
      {
        // Less precise: use record TTL as approximation instead of SOA MINIMUM field
        // This is acceptable but not ideal - log a warning for monitoring
        iora::core::Logger::debug("DNS negative TTL using SOA record TTL approximation (SOA parsing may have failed)");
        return record.ttl;
      }
    }
    
    // RFC 2308 fallback: use default negative TTL when no SOA found
    return defaultNegativeTtl;
  }

  /// \brief Calculate appropriate TTL from DNS result using conservative minimum approach
  /// 
  /// This method implements the conservative caching strategy by returning the minimum TTL
  /// across all resource records in the DNS response. This ensures that the cached entry
  /// expires when the first record would become stale, maintaining DNS correctness.
  /// 
  /// Alternative approaches could include:
  /// - Per-record TTL caching: Store each record type separately with individual TTLs
  /// - Weighted TTL: Use TTL from the most "important" record type for the query
  /// - Configurable strategy: Allow applications to choose caching granularity
  /// 
  /// \param result DNS query result containing multiple resource records
  /// \return TTL in seconds (minimum across all records, default 300s if none found)
  std::uint32_t calculateResultTtl(const DnsResult& result) const
  {
    std::uint32_t min_ttl = std::numeric_limits<std::uint32_t>::max();
    
    // Check all raw record sections (RFC 1035 sections)
    for (const auto& record : result.answers)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.authority)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.additional)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    // Check all typed record collections (comprehensive coverage)
    for (const auto& record : result.a_records)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.aaaa_records)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.srv_records)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.naptr_records)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.cname_records)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.mx_records)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.txt_records)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.ptr_records)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    for (const auto& record : result.soa_records)
    {
      min_ttl = std::min(min_ttl, record.ttl);
    }
    
    // Default TTL if no records found (RFC 1035 suggests reasonable defaults)
    if (min_ttl == std::numeric_limits<std::uint32_t>::max())
    {
      min_ttl = 300; // 5 minutes default
    }
    
    return min_ttl;
  }
};

} // namespace dns
} // namespace network  
} // namespace iora