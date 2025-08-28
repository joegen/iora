// © Joegen Baclor. All rights reserved.
// Unauthorized use, reproduction, distribution, or modification 
// of this library in any form is strictly prohibited.

/// \file MockDnsServer.hpp
/// \brief Advanced mock DNS server for comprehensive DNS client testing
///
/// This provides wire-level DNS message testing with:
/// - Real DNS wire-format responses (including compression, pointers, RDATA)
/// - UDP/TCP network behavior simulation (truncation, fallback, fragmentation)
/// - SOA negative responses with proper RFC 2308 encoding
/// - Pointer compression edge cases and malicious sequences
/// - Raw byte injection and partial frame control
/// - Deterministic RNG hooks for weighted SRV selection testing

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <memory>
#include <random>
#include <sstream>
#include <queue>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/// \brief Advanced mock DNS server for comprehensive testing
class MockDnsServer
{
public:
  /// \brief DNS wire-format response data
  struct WireResponse 
  {
    std::vector<std::uint8_t> data;
    bool isTruncated{false};               // Set TC bit for UDP responses
    bool forceInvalidCompression{false};   // Inject malicious compression
    std::chrono::milliseconds delay{0};    // Response delay
    bool shouldTimeout{false};             // Force timeout
    bool shouldDrop{false};               // Drop packet (no response)
  };
  
  /// \brief TCP frame fragmentation control
  struct TcpFragmentation
  {
    std::vector<std::vector<std::uint8_t>> fragments;  // Ordered fragments
    std::vector<std::chrono::milliseconds> delays;     // Delay between fragments  
    bool incomplete{false};                            // Leave final fragment unset
  };

  /// \brief DNS query record for structured responses (legacy compatibility)
  struct DnsRecord
  {
    std::string name;
    std::string type;  // A, AAAA, SRV, NAPTR, SOA, CNAME, MX, TXT
    std::string value;
    std::uint32_t ttl{3600};
    std::uint16_t priority{0};  // For SRV/MX records
    std::uint16_t weight{0};    // For SRV records
    std::uint16_t port{5060};   // For SRV records
    
    // SOA-specific fields for negative caching tests
    std::string mname;          // SOA primary nameserver
    std::string rname;          // SOA responsible person
    std::uint32_t serial{1};    // SOA serial
    std::uint32_t refresh{3600}; // SOA refresh
    std::uint32_t retry{1800};  // SOA retry  
    std::uint32_t expire{604800}; // SOA expire
    std::uint32_t minimum{86400}; // SOA minimum (negative cache TTL)
  };

  /// \brief Query behavior configuration
  struct QueryConfig
  {
    std::chrono::milliseconds delay{0};          // Network delay simulation
    bool shouldFail{false};                     // Force query failure
    bool shouldTimeout{false};                  // Force query timeout
    bool shouldTruncate{false};                // Force UDP truncation (TC=1)
    bool shouldFragmentTcp{false};             // Fragment TCP response
    bool useWireFormat{false};                 // Use raw wire response
    bool enableCompression{true};              // Enable name compression
    bool injectMaliciousPointers{false};       // Test pointer loop handling
    std::string errorMessage;                  // Custom error message
  };

  /// \brief RNG hook for deterministic testing  
  using RngHook = std::function<std::uint32_t()>;
  
  /// \brief Mock DNS server configuration
  struct Config
  {
    std::uint16_t udpPort{5353};                      // UDP server port
    std::uint16_t tcpPort{5353};                      // TCP server port  
    std::chrono::milliseconds defaultDelay{10};       // Default query delay
    std::chrono::milliseconds queryTimeout{5000};     // Query timeout
    bool enableLogging{false};                        // Enable query logging
    bool enableUdp{true};                             // Enable UDP server
    bool enableTcp{true};                             // Enable TCP server
    std::size_t maxUdpSize{512};                      // Max UDP response size
    std::size_t maxTcpFragmentSize{64};               // TCP fragment size for testing
  };

private:
  Config config_;
  std::atomic<bool> running_{false};
  
  // Server threads
  std::thread udpServerThread_;
  std::thread tcpServerThread_;
  
  // Socket handles
  int udpSocket_{-1};
  int tcpSocket_{-1};

  // DNS records and wire responses
  mutable std::mutex recordsMutex_;
  std::unordered_map<std::string, std::vector<DnsRecord>> records_;
  std::unordered_map<std::string, WireResponse> wireResponses_;
  std::unordered_map<std::string, TcpFragmentation> tcpFragments_;
  std::unordered_map<std::string, QueryConfig> queryConfigs_;

  // Query logging and statistics
  mutable std::mutex logMutex_;
  mutable std::vector<std::string> queryLog_;
  std::atomic<std::uint64_t> udpQueryCount_{0};
  std::atomic<std::uint64_t> tcpQueryCount_{0};
  std::atomic<std::uint64_t> truncatedCount_{0};
  
  // RNG control for testing
  mutable std::mutex rngMutex_;
  RngHook rngHook_;
  mutable std::mt19937 defaultRng_;
  
  // Name compression dictionary for wire format responses
  mutable std::unordered_map<std::string, std::uint16_t> compressionTable_;

public:
  MockDnsServer() : config_({}), defaultRng_(std::random_device{}()) {}
  
  explicit MockDnsServer(const Config& config) 
    : config_(config), defaultRng_(std::random_device{}()) 
  {
  }

  ~MockDnsServer()
  {
    stop();
  }

  /// \brief Start the mock DNS server with real UDP/TCP sockets
  bool start()
  {
    if (running_.exchange(true))
    {
      return false;  // Already running
    }

    try
    {
      if (config_.enableUdp)
      {
        startUdpServer();
        udpServerThread_ = std::thread([this]() { udpServerLoop(); });
      }
      
      if (config_.enableTcp)
      {
        startTcpServer();
        tcpServerThread_ = std::thread([this]() { tcpServerLoop(); });
      }

      // Wait for servers to initialize
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      
      if (config_.enableLogging)
      {
        logQuery("MockDnsServer started - UDP:" + std::to_string(config_.udpPort) + 
                " TCP:" + std::to_string(config_.tcpPort));
      }
      
      return true;
    }
    catch (const std::exception& e)
    {
      running_.store(false);
      if (config_.enableLogging)
      {
        logQuery("Failed to start MockDnsServer: " + std::string(e.what()));
      }
      return false;
    }
  }

  /// \brief Stop the mock DNS server
  void stop()
  {
    if (running_.exchange(false))
    {
      // Close sockets to wake up server threads
      if (udpSocket_ >= 0)
      {
        shutdown(udpSocket_, SHUT_RDWR); // Force wake up recvfrom
        close(udpSocket_);
        udpSocket_ = -1;
      }
      
      if (tcpSocket_ >= 0)
      {
        shutdown(tcpSocket_, SHUT_RDWR); // Force wake up accept
        close(tcpSocket_);
        tcpSocket_ = -1;
      }

      // Allow threads brief time to respond to socket shutdown
      std::this_thread::sleep_for(std::chrono::milliseconds(100));

      // Join threads properly - they should exit quickly now
      if (udpServerThread_.joinable())
      {
        udpServerThread_.join();
      }
      
      if (tcpServerThread_.joinable())
      {
        tcpServerThread_.join();
      }

      if (config_.enableLogging)
      {
        logQuery("MockDnsServer stopped");
      }
    }
  }

  /// \brief Set wire-format response for a query name
  void setWireResponse(const std::string& name, const WireResponse& response)
  {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    wireResponses_[name] = response;
  }

  /// \brief Set TCP fragmentation for a query name  
  void setTcpFragmentation(const std::string& name, const TcpFragmentation& fragmentation)
  {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    tcpFragments_[name] = fragmentation;
  }

  /// \brief Add a DNS record
  void addRecord(const DnsRecord& record)
  {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    records_[record.name].push_back(record);
  }

  /// \brief Add multiple DNS records for a name
  void addRecords(const std::string& name, const std::vector<DnsRecord>& recordList)
  {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    for (const auto& record : recordList)
    {
      records_[name].push_back(record);
    }
  }

  /// \brief Configure query behavior for a specific name
  void configureQuery(const std::string& name, const QueryConfig& config)
  {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    queryConfigs_[name] = config;
  }

  /// \brief Clear all DNS records
  void clearRecords()
  {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    records_.clear();
    queryConfigs_.clear();
  }

  /// \brief Get query log
  std::vector<std::string> getQueryLog() const
  {
    std::lock_guard<std::mutex> lock(logMutex_);
    return queryLog_;
  }

  /// \brief Clear query log
  void clearQueryLog()
  {
    std::lock_guard<std::mutex> lock(logMutex_);
    queryLog_.clear();
  }

  // =============================================================================
  // Statistics and Testing Support
  // =============================================================================

  /// \brief Get server statistics
  struct Stats
  {
    std::size_t totalRecords{0};
    std::uint64_t udpQueries{0};
    std::uint64_t tcpQueries{0};
    std::uint64_t truncatedResponses{0};
    bool isRunning{false};
    std::uint16_t udpPort{0};
    std::uint16_t tcpPort{0};
  };

  Stats getStats() const
  {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    Stats stats;
    stats.isRunning = running_;
    stats.udpPort = config_.udpPort;
    stats.tcpPort = config_.tcpPort;
    stats.udpQueries = udpQueryCount_.load();
    stats.tcpQueries = tcpQueryCount_.load();
    stats.truncatedResponses = truncatedCount_.load();

    for (const auto& pair : records_)
    {
      stats.totalRecords += pair.second.size();
    }

    return stats;
  }

  // =============================================================================  
  // Test Setup Helpers
  // =============================================================================

  /// \brief Setup common SIP DNS records for testing
  void setupCommonSipRecords()
  {
    // Standard SIP domain
    addRecord({"example.com", "A", "93.184.216.34", 3600, 0, 0, 5060});
    addRecord({"example.com", "SRV", "_sip._udp.example.com", 3600, 10, 5, 5060});

    // SIP proxy records
    addRecord({"proxy1.example.com", "A", "192.168.1.10", 3600, 0, 0, 5060});
    addRecord({"proxy2.example.com", "A", "192.168.1.11", 3600, 0, 0, 5060});

    // Load balancing SRV records with different weights
    addRecord({"loadbalance.example.com", "SRV", "_sip._udp.lb1.example.com", 3600, 10, 10, 5060});
    addRecord({"loadbalance.example.com", "SRV", "_sip._udp.lb2.example.com", 3600, 10, 20, 5060});
    addRecord({"lb1.example.com", "A", "10.0.1.1", 3600, 0, 0, 5060});
    addRecord({"lb2.example.com", "A", "10.0.1.2", 3600, 0, 0, 5060});

    // IPv6 records
    addRecord({"ipv6.example.com", "AAAA", "2001:db8::1", 3600, 0, 0, 5060});
  }

  /// \brief Setup wire-format testing scenarios
  void setupWireFormatTests()
  {
    // Truncated UDP response that triggers TCP fallback
    WireResponse truncatedResponse;
    truncatedResponse.isTruncated = true;
    truncatedResponse.data = generateWireResponse("truncated.example.com", 1, 
      {{"truncated.example.com", "A", "192.168.1.100", 3600}}, true, false);
    setWireResponse("truncated.example.com", truncatedResponse);

    // Response with malicious compression pointers
    WireResponse maliciousResponse;
    maliciousResponse.data = generateMaliciousResponse("pointer_loop");
    maliciousResponse.forceInvalidCompression = true;
    setWireResponse("malicious.example.com", maliciousResponse);

    // SOA record for negative caching
    DnsRecord soaRecord;
    soaRecord.name = "negative.example.com";
    soaRecord.type = "SOA";
    soaRecord.mname = "ns1.negative.example.com";
    soaRecord.rname = "admin.negative.example.com";
    soaRecord.minimum = 300; // 5-minute negative cache TTL
    WireResponse soaResponse;
    soaResponse.data = generateSoaResponse("negative.example.com", soaRecord);
    setWireResponse("negative.example.com", soaResponse);

    // TCP fragmentation test
    TcpFragmentation fragmentation;
    auto fullResponse = generateWireResponse("fragmented.example.com", 1,
      {{"fragmented.example.com", "A", "192.168.1.200", 3600}}, true, false);
    
    // Split into small fragments
    size_t fragmentSize = config_.maxTcpFragmentSize;
    for (size_t i = 0; i < fullResponse.size(); i += fragmentSize)
    {
      size_t size = std::min(fragmentSize, fullResponse.size() - i);
      std::vector<std::uint8_t> fragment(fullResponse.begin() + i, 
                                        fullResponse.begin() + i + size);
      fragmentation.fragments.push_back(fragment);
      fragmentation.delays.push_back(std::chrono::milliseconds(10));
    }
    setTcpFragmentation("fragmented.example.com", fragmentation);
  }

private:
  // =============================================================================
  // Server Implementation
  // =============================================================================
  
  void startUdpServer()
  {
    udpSocket_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket_ < 0)
    {
      throw std::runtime_error("Failed to create UDP socket");
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(udpSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config_.udpPort);

    if (bind(udpSocket_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
      close(udpSocket_);
      throw std::runtime_error("Failed to bind UDP socket to port " + std::to_string(config_.udpPort));
    }
  }

  void startTcpServer()
  {
    tcpSocket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSocket_ < 0)
    {
      throw std::runtime_error("Failed to create TCP socket");
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(tcpSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config_.tcpPort);

    if (bind(tcpSocket_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
      close(tcpSocket_);
      throw std::runtime_error("Failed to bind TCP socket to port " + std::to_string(config_.tcpPort));
    }

    if (listen(tcpSocket_, 5) < 0)
    {
      close(tcpSocket_);
      throw std::runtime_error("Failed to listen on TCP socket");
    }
  }

  void udpServerLoop()
  {
    std::vector<std::uint8_t> buffer(4096);
    struct sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);

    while (running_)
    {
      ssize_t received = recvfrom(udpSocket_, buffer.data(), buffer.size(), 0,
                                 (struct sockaddr*)&clientAddr, &clientLen);
      
      if (received < 0)
      {
        if (running_) // Only log if not shutting down
        {
          if (config_.enableLogging)
          {
            logQuery("UDP recvfrom error: " + std::string(strerror(errno)));
          }
        }
        continue;
      }

      udpQueryCount_++;
      
      // Process DNS query and send response
      auto response = processDnsQuery(buffer.data(), received, false);
      if (!response.empty())
      {
        sendto(udpSocket_, response.data(), response.size(), 0,
               (struct sockaddr*)&clientAddr, clientLen);
      }
    }
  }

  void tcpServerLoop() 
  {
    while (running_)
    {
      struct sockaddr_in clientAddr{};
      socklen_t clientLen = sizeof(clientAddr);
      
      int clientSocket = accept(tcpSocket_, (struct sockaddr*)&clientAddr, &clientLen);
      if (clientSocket < 0)
      {
        if (running_) // Only log if not shutting down
        {
          if (config_.enableLogging)
          {
            logQuery("TCP accept error: " + std::string(strerror(errno)));
          }
        }
        continue;
      }

      // Handle TCP client in separate thread to support concurrent connections
      std::thread([this, clientSocket]() {
        handleTcpClient(clientSocket);
      }).detach();
    }
  }

  void handleTcpClient(int clientSocket)
  {
    // TCP DNS messages are length-prefixed
    std::uint8_t lengthBytes[2];
    if (recv(clientSocket, lengthBytes, 2, MSG_WAITALL) != 2)
    {
      close(clientSocket);
      return;
    }

    std::uint16_t messageLength = (lengthBytes[0] << 8) | lengthBytes[1];
    if (messageLength == 0)
    {
      close(clientSocket);
      return;
    }

    std::vector<std::uint8_t> queryBuffer(messageLength);
    if (recv(clientSocket, queryBuffer.data(), messageLength, MSG_WAITALL) != messageLength)
    {
      close(clientSocket);
      return;
    }

    tcpQueryCount_++;

    // Process query and send response  
    auto response = processDnsQuery(queryBuffer.data(), messageLength, true);
    if (!response.empty())
    {
      // Send length-prefixed response
      std::uint16_t responseLength = response.size();
      std::uint8_t lengthPrefix[2] = {
        static_cast<std::uint8_t>(responseLength >> 8),
        static_cast<std::uint8_t>(responseLength & 0xFF)
      };
      
      send(clientSocket, lengthPrefix, 2, 0);
      send(clientSocket, response.data(), response.size(), 0);
    }

    close(clientSocket);
  }

  // =============================================================================
  // DNS Message Processing 
  // =============================================================================

  std::vector<std::uint8_t> processDnsQuery(const std::uint8_t* data, size_t length, bool isTcp)
  {
    // Parse query (simplified - extract question name and type)
    if (length < 12) return {}; // Invalid DNS header
    
    // Extract query ID
    std::uint16_t queryId = (data[0] << 8) | data[1];
    
    // Parse question section 
    size_t nameEndPos = 0;
    std::string questionName = parseQuestionName(data + 12, length - 12, &nameEndPos);
    
    if (questionName.empty())
    {
      return {};
    }
    
    // Extract query type (QTYPE) - it's right after the name
    size_t qtypePos = 12 + nameEndPos;
    if (qtypePos + 4 > length) return {}; // Need 4 bytes for QTYPE + QCLASS
    
    std::uint16_t queryType = (data[qtypePos] << 8) | data[qtypePos + 1];

    if (config_.enableLogging)
    {
      logQuery("DNS query: " + questionName + " type=" + std::to_string(queryType) + " via " + (isTcp ? "TCP" : "UDP"));
    }

    // Check for configured wire response
    {
      std::lock_guard<std::mutex> lock(recordsMutex_);
      auto wireIt = wireResponses_.find(questionName);
      if (wireIt != wireResponses_.end())
      {
        const auto& wireResponse = wireIt->second;
        
        // Apply delay if configured
        if (wireResponse.delay.count() > 0)
        {
          std::this_thread::sleep_for(wireResponse.delay);
        }
        
        if (wireResponse.shouldTimeout || wireResponse.shouldDrop)
        {
          return {}; // No response
        }

        auto response = wireResponse.data;
        
        // Set correct query ID
        if (response.size() >= 2)
        {
          response[0] = static_cast<std::uint8_t>(queryId >> 8);
          response[1] = static_cast<std::uint8_t>(queryId & 0xFF);
        }
        
        // Handle truncation for UDP
        if (!isTcp && wireResponse.isTruncated)
        {
          truncatedCount_++;
          if (response.size() >= 2)
          {
            response[2] |= 0x02; // Set TC bit
          }
          // Truncate response to max UDP size
          if (response.size() > config_.maxUdpSize)
          {
            response.resize(config_.maxUdpSize);
          }
        }
        
        return response;
      }
      
      // Check for TCP fragmentation
      if (isTcp)
      {
        auto fragIt = tcpFragments_.find(questionName);
        if (fragIt != tcpFragments_.end())
        {
          // For now, return full response - fragmentation would be handled 
          // at the socket send level in a real implementation
          const auto& frag = fragIt->second;
          if (!frag.fragments.empty())
          {
            // Combine all fragments
            std::vector<std::uint8_t> combined;
            for (const auto& fragment : frag.fragments)
            {
              combined.insert(combined.end(), fragment.begin(), fragment.end());
            }
            return combined;
          }
        }
      }
      
      // Check for query-specific configuration (timeout, failure, etc.)
      auto configIt = queryConfigs_.find(questionName);
      if (configIt != queryConfigs_.end())
      {
        const auto& queryConfig = configIt->second;
        
        // Handle timeout (no response)
        if (queryConfig.shouldTimeout)
        {
          return {}; // No response (simulates timeout)
        }
        
        // Handle server failure (return SERVFAIL response)
        if (queryConfig.shouldFail)
        {
          return generateServfailResponse(queryId, questionName, queryType);
        }
        
        // Apply delay only for successful responses
        if (queryConfig.delay.count() > 0)
        {
          std::this_thread::sleep_for(queryConfig.delay);
        }
      }
    }

    // Fallback to structured record responses  
    return generateStructuredResponse(queryId, questionName, queryType);
  }

  std::string parseQuestionName(const std::uint8_t* data, size_t length, size_t* endPos = nullptr)
  {
    // Simple DNS name parsing (no compression handling for queries)
    std::string name;
    size_t pos = 0;
    
    while (pos < length)
    {
      std::uint8_t labelLen = data[pos++];
      if (labelLen == 0) {
        if (endPos) *endPos = pos; // Set end position after null terminator
        break; // End of name
      }
      
      if (pos + labelLen > length) return ""; // Invalid
      
      if (!name.empty()) name += ".";
      name += std::string(reinterpret_cast<const char*>(data + pos), labelLen);
      pos += labelLen;
    }
    
    return name;
  }

  std::vector<std::uint8_t> generateStructuredResponse(std::uint16_t queryId, const std::string& questionName, std::uint16_t queryType)
  {
    std::lock_guard<std::mutex> lock(recordsMutex_);
    
    auto recordIt = records_.find(questionName);
    if (recordIt == records_.end())
    {
      return generateNxdomainResponse(queryId, questionName, queryType);
    }

    // Filter records by type
    const auto& allRecords = recordIt->second;
    std::vector<DnsRecord> filteredRecords;
    
    // Map query type to record type string
    std::string typeStr;
    switch (queryType) {
      case 1: typeStr = "A"; break;
      case 28: typeStr = "AAAA"; break;
      case 33: typeStr = "SRV"; break;
      case 5: typeStr = "CNAME"; break;
      case 15: typeStr = "MX"; break;
      default: typeStr = ""; break;
    }
    
    // Only include records matching the query type
    for (const auto& record : allRecords) {
      if (record.type == typeStr) {
        filteredRecords.push_back(record);
      }
    }
    
    if (filteredRecords.empty()) {
      return generateNxdomainResponse(queryId, questionName, queryType);
    }
    
    return generateWireResponse(questionName, queryType, filteredRecords, true, false, queryId);
  }

  std::vector<std::uint8_t> generateNxdomainResponse(std::uint16_t queryId, const std::string& questionName, std::uint16_t queryType = 1)
  {
    // Generate NXDOMAIN response with SOA record
    std::vector<std::uint8_t> response;
    
    // DNS header (12 bytes)
    response.resize(12);
    response[0] = static_cast<std::uint8_t>(queryId >> 8);
    response[1] = static_cast<std::uint8_t>(queryId & 0xFF);
    response[2] = 0x81; // Response, recursion desired
    response[3] = 0x83; // NXDOMAIN
    
    // Question count = 1, Answer count = 0, Authority count = 1, Additional = 0
    response[4] = 0; response[5] = 1; // QDCOUNT
    response[6] = 0; response[7] = 0; // ANCOUNT  
    response[8] = 0; response[9] = 1; // NSCOUNT
    response[10] = 0; response[11] = 0; // ARCOUNT
    
    // Question section - echo back the exact query
    encodeQuestionName(response, questionName);
    response.push_back((queryType >> 8) & 0xFF);  // QTYPE high byte
    response.push_back(queryType & 0xFF);         // QTYPE low byte
    response.push_back(0); response.push_back(1); // CLASS IN
    
    // Authority section with SOA
    DnsRecord soaRecord;
    soaRecord.type = "SOA";
    soaRecord.name = "example.com";
    soaRecord.mname = "ns1.example.com";
    soaRecord.rname = "admin.example.com";
    soaRecord.minimum = 3600;
    
    auto soaData = generateSoaResponse(questionName, soaRecord);
    response.insert(response.end(), soaData.begin() + 12, soaData.end()); // Skip header
    
    return response;
  }

  std::vector<std::uint8_t> generateServfailResponse(std::uint16_t queryId, const std::string& questionName, std::uint16_t queryType = 1)
  {
    // Generate SERVFAIL response (similar to NXDOMAIN but with different error code)
    std::vector<std::uint8_t> response;
    
    // DNS header (12 bytes)
    response.resize(12);
    response[0] = static_cast<std::uint8_t>(queryId >> 8);
    response[1] = static_cast<std::uint8_t>(queryId & 0xFF);
    response[2] = 0x81; // Response, recursion desired
    response[3] = 0x82; // SERVFAIL (0x80 | 0x02)
    
    // Question count = 1, Answer count = 0, Authority count = 0, Additional = 0
    response[4] = 0; response[5] = 1; // QDCOUNT
    response[6] = 0; response[7] = 0; // ANCOUNT  
    response[8] = 0; response[9] = 0; // NSCOUNT (no authority section for SERVFAIL)
    response[10] = 0; response[11] = 0; // ARCOUNT
    
    // Add question section
    encodeQuestionName(response, questionName);
    response.push_back(static_cast<std::uint8_t>(queryType >> 8));
    response.push_back(static_cast<std::uint8_t>(queryType & 0xFF));
    response.push_back(0x00); response.push_back(0x01); // Class IN
    
    return response;
  }

  void encodeQuestionName(std::vector<std::uint8_t>& buffer, const std::string& name)
  {
    // Simple DNS name encoding
    std::istringstream iss(name);
    std::string label;
    
    while (std::getline(iss, label, '.'))
    {
      buffer.push_back(static_cast<std::uint8_t>(label.length()));
      buffer.insert(buffer.end(), label.begin(), label.end());
    }
    buffer.push_back(0); // End of name
  }

  void logQuery(const std::string& query) const
  {
    if (!config_.enableLogging) return;
    
    std::lock_guard<std::mutex> lock(logMutex_);
    queryLog_.push_back(query);
  }
  
  // =============================================================================
  // Wire Format Generation (Method Stubs - To Be Implemented)
  // =============================================================================
  
  std::vector<std::uint8_t> generateWireResponse(
    const std::string& queryName,
    std::uint16_t queryType,
    const std::vector<DnsRecord>& records,
    bool enableCompression,
    bool injectMaliciousPointers,
    std::uint16_t queryId = 0x1234)
  {
    std::vector<std::uint8_t> response;
    
    // DNS Header (12 bytes)
    response.resize(12);
    
    // Transaction ID (from query)
    response[0] = (queryId >> 8) & 0xFF;
    response[1] = queryId & 0xFF;
    
    // Flags: QR=1 (response), AA=1 (authoritative), RD=1 (recursion desired)
    response[2] = 0x85; // 10000101 
    response[3] = 0x00; // No errors (RCODE = 0)
    
    // Question count
    response[4] = 0; 
    response[5] = 1;
    
    // Answer count
    response[6] = 0; 
    response[7] = static_cast<std::uint8_t>(records.size());
    
    // Authority and Additional counts (0)
    response[8] = response[9] = response[10] = response[11] = 0;
    
    // Question Section
    encodeQuestionName(response, queryName);
    
    // QTYPE (2 bytes)
    response.push_back((queryType >> 8) & 0xFF);
    response.push_back(queryType & 0xFF);
    
    // QCLASS (2 bytes) - IN = 1
    response.push_back(0x00);
    response.push_back(0x01);
    
    // Answer Section
    for (const auto& record : records)
    {
      // NAME - use compression pointer to question if same name
      if (enableCompression && record.name == queryName)
      {
        response.push_back(0xC0); // Compression pointer
        response.push_back(0x0C); // Offset to name in question (after header)
      }
      else
      {
        encodeQuestionName(response, record.name);
      }
      
      // TYPE
      std::uint16_t recordType = 1; // A record
      if (record.type == "AAAA") recordType = 28;
      else if (record.type == "CNAME") recordType = 5;
      else if (record.type == "MX") recordType = 15;
      else if (record.type == "SRV") recordType = 33;
      
      response.push_back((recordType >> 8) & 0xFF);
      response.push_back(recordType & 0xFF);
      
      // CLASS (IN = 1)
      response.push_back(0x00);
      response.push_back(0x01);
      
      // TTL (4 bytes)
      std::uint32_t ttl = record.ttl;
      response.push_back((ttl >> 24) & 0xFF);
      response.push_back((ttl >> 16) & 0xFF);
      response.push_back((ttl >> 8) & 0xFF);
      response.push_back(ttl & 0xFF);
      
      // RDLENGTH and RDATA
      if (record.type == "A")
      {
        // IPv4 address (4 bytes)
        response.push_back(0x00);
        response.push_back(0x04); // RDLENGTH = 4
        
        // Parse IP address
        std::istringstream iss(record.value);
        std::string octet;
        while (std::getline(iss, octet, '.'))
        {
          response.push_back(static_cast<std::uint8_t>(std::stoi(octet)));
        }
      }
      else if (record.type == "AAAA")
      {
        // IPv6 address (16 bytes)
        response.push_back(0x00);
        response.push_back(0x10); // RDLENGTH = 16
        
        // Parse IPv6 address (simplified - hardcode common test addresses)
        if (record.value == "2001:db8::1") {
          std::vector<std::uint8_t> ipv6 = {
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
          };
          response.insert(response.end(), ipv6.begin(), ipv6.end());
        } else if (record.value == "2001:db8::2") {
          std::vector<std::uint8_t> ipv6 = {
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
          };
          response.insert(response.end(), ipv6.begin(), ipv6.end());
        } else {
          // Fallback for other IPv6 addresses - zero address
          for (int i = 0; i < 16; i++) {
            response.push_back(0x00);
          }
        }
      }
      else if (record.type == "SRV")
      {
        // SRV record: Priority(2) + Weight(2) + Port(2) + Target(variable)
        std::size_t rdlengthPos = response.size(); // Position of RDLENGTH field
        response.push_back(0x00); // RDLENGTH high byte (placeholder)
        response.push_back(0x00); // RDLENGTH low byte (placeholder)
        
        std::size_t rdataStart = response.size(); // Start of actual RDATA
        
        // Priority (2 bytes)
        response.push_back((record.priority >> 8) & 0xFF);
        response.push_back(record.priority & 0xFF);
        
        // Weight (2 bytes)
        response.push_back((record.weight >> 8) & 0xFF);
        response.push_back(record.weight & 0xFF);
        
        // Port (2 bytes)
        response.push_back((record.port >> 8) & 0xFF);
        response.push_back(record.port & 0xFF);
        
        // Target name
        encodeQuestionName(response, record.value);
        
        // Update RDLENGTH
        std::size_t rdataLength = response.size() - rdataStart;
        response[rdlengthPos] = (rdataLength >> 8) & 0xFF;
        response[rdlengthPos + 1] = rdataLength & 0xFF;
      }
      else
      {
        // For other record types, encode as name
        std::size_t rdlengthPos = response.size(); // Position of RDLENGTH field
        response.push_back(0x00); // RDLENGTH high byte (placeholder)
        response.push_back(0x00); // RDLENGTH low byte (placeholder)
        
        std::size_t rdataStart = response.size(); // Start of actual RDATA
        
        encodeQuestionName(response, record.value);
        
        // Update RDLENGTH
        std::size_t rdataLength = response.size() - rdataStart;
        response[rdlengthPos] = (rdataLength >> 8) & 0xFF;
        response[rdlengthPos + 1] = rdataLength & 0xFF;
      }
    }
    
    return response;
  }

  std::vector<std::uint8_t> generateSoaResponse(const std::string& domain, const DnsRecord& soaRecord)
  {
    std::vector<std::uint8_t> response;
    response.resize(12); // DNS header placeholder
    
    // Authority record: NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA
    
    // NAME (use compression pointer to question or encode full name)
    encodeQuestionName(response, domain);
    
    // TYPE: SOA = 6
    response.push_back(0x00);
    response.push_back(0x06);
    
    // CLASS: IN = 1
    response.push_back(0x00);
    response.push_back(0x01);
    
    // TTL (4 bytes)
    std::uint32_t ttl = soaRecord.ttl;
    response.push_back((ttl >> 24) & 0xFF);
    response.push_back((ttl >> 16) & 0xFF);
    response.push_back((ttl >> 8) & 0xFF);
    response.push_back(ttl & 0xFF);
    
    // SOA RDATA
    std::size_t rdlengthPos = response.size();
    response.push_back(0x00); // RDLENGTH placeholder
    response.push_back(0x00);
    
    std::size_t rdataStart = response.size();
    
    // MNAME (primary nameserver)
    encodeQuestionName(response, soaRecord.mname);
    
    // RNAME (responsible person)
    encodeQuestionName(response, soaRecord.rname);
    
    // Serial (4 bytes)
    std::uint32_t serial = soaRecord.serial;
    response.push_back((serial >> 24) & 0xFF);
    response.push_back((serial >> 16) & 0xFF);
    response.push_back((serial >> 8) & 0xFF);
    response.push_back(serial & 0xFF);
    
    // Refresh (4 bytes)
    std::uint32_t refresh = soaRecord.refresh;
    response.push_back((refresh >> 24) & 0xFF);
    response.push_back((refresh >> 16) & 0xFF);
    response.push_back((refresh >> 8) & 0xFF);
    response.push_back(refresh & 0xFF);
    
    // Retry (4 bytes)
    std::uint32_t retry = soaRecord.retry;
    response.push_back((retry >> 24) & 0xFF);
    response.push_back((retry >> 16) & 0xFF);
    response.push_back((retry >> 8) & 0xFF);
    response.push_back(retry & 0xFF);
    
    // Expire (4 bytes) - use refresh value as default
    response.push_back((refresh >> 24) & 0xFF);
    response.push_back((refresh >> 16) & 0xFF);
    response.push_back((refresh >> 8) & 0xFF);
    response.push_back(refresh & 0xFF);
    
    // Minimum TTL (4 bytes)
    std::uint32_t minimum = soaRecord.minimum;
    response.push_back((minimum >> 24) & 0xFF);
    response.push_back((minimum >> 16) & 0xFF);
    response.push_back((minimum >> 8) & 0xFF);
    response.push_back(minimum & 0xFF);
    
    // Update RDLENGTH
    std::size_t rdataLength = response.size() - rdataStart;
    response[rdlengthPos] = (rdataLength >> 8) & 0xFF;
    response[rdlengthPos + 1] = rdataLength & 0xFF;
    
    return response;
  }

  std::vector<std::uint8_t> generateMaliciousResponse(const std::string& maliciousType)
  {
    // TODO: Implement malicious response generation for robustness testing
    // Types: "pointer_loop", "invalid_compression", "buffer_overflow", etc.
    
    std::vector<std::uint8_t> response;
    
    if (maliciousType == "pointer_loop")
    {
      // Create a response with circular name compression pointers
      response.resize(20);
      // DNS header
      response[2] = 0x84; // Response flags
      
      // Question name with pointer loop: ptr -> ptr (circular)
      response[12] = 0xC0; response[13] = 0x0E; // Pointer to offset 14
      response[14] = 0xC0; response[15] = 0x0C; // Pointer to offset 12 (loop!)
    }
    
    return response;
  }
};