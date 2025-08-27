// Minimal real DNS server for testing
// Listens on UDP port 5353 and provides dummy responses for test domains

#pragma once

#include <atomic>
#include <thread>
#include <unordered_map>
#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

class MinimalDnsServer
{
private:
    std::atomic<bool> running_{false};
    std::thread serverThread_;
    int sockfd_{-1};
    uint16_t port_{5353};
    
    // Dummy DNS records for test domains
    std::unordered_map<std::string, std::string> testRecords_ = {
        {"google.com", "8.8.8.8"},
        {"example.com", "93.184.216.34"}, 
        {"cloudflare.com", "1.1.1.1"},
        {"test.com", "192.168.1.1"},
        {"localhost", "127.0.0.1"}
    };

    // DNS header structure
    struct DnsHeader {
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
    };

    void serverLoop() {
        sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd_ < 0) {
            return;
        }

        int reuse = 1;
        setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port_);

        if (bind(sockfd_, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            std::cout << "MinimalDnsServer: Failed to bind to port " << port_ << ": " << errno << std::endl;
            close(sockfd_);
            return;
        }
        std::cout << "MinimalDnsServer: Successfully bound to port " << port_ << std::endl; 
        std::cout.flush();

        uint8_t buffer[512];
        sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);

        while (running_) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sockfd_, &readfds);
            
            timeval timeout{0, 100000}; // 100ms timeout
            int result = select(sockfd_ + 1, &readfds, nullptr, nullptr, &timeout);
            
            if (result <= 0) {
                // std::cout << "MinimalDnsServer: select timeout or error" << std::endl;
                continue;
            }
            
            std::cout << "MinimalDnsServer: select returned " << result << ", about to recvfrom" << std::endl;

            ssize_t bytesReceived = recvfrom(sockfd_, buffer, sizeof(buffer), 0,
                                           (sockaddr*)&clientAddr, &clientLen);
            
            std::cout << "MinimalDnsServer: Received " << bytesReceived << " bytes from " 
                      << inet_ntoa(clientAddr.sin_addr) << ":" << ntohs(clientAddr.sin_port) << std::endl;
            std::cout.flush();
            std::cout << "MinimalDnsServer: DnsHeader size is " << sizeof(DnsHeader) << " bytes" << std::endl;
            std::cout.flush();
            
            if (bytesReceived >= 12) { // DNS header is always 12 bytes
                std::cout << "MinimalDnsServer: Processing query (received " << bytesReceived << " bytes)" << std::endl;
                std::cout.flush();
                handleQuery(buffer, bytesReceived, clientAddr, clientLen);
                std::cout << "MinimalDnsServer: handleQuery completed" << std::endl;
                std::cout.flush();
            } else {
                std::cout << "MinimalDnsServer: Packet too small (" << bytesReceived 
                          << " < 12), ignoring" << std::endl;
                std::cout.flush();
            }
        }

        if (sockfd_ >= 0) {
            close(sockfd_);
            sockfd_ = -1;
        }
    }

    void handleQuery(uint8_t* query, size_t queryLen, 
                    const sockaddr_in& clientAddr, socklen_t clientLen) {
        std::cout << "MinimalDnsServer: handleQuery called with " << queryLen << " bytes" << std::endl;
        std::cout.flush();
        if (queryLen < 17) {
            std::cout << "MinimalDnsServer: Query too small, returning" << std::endl;
            std::cout.flush();
            return; // Minimum query size (12 byte header + 5 bytes for minimal question)
        }

        DnsHeader* header = reinterpret_cast<DnsHeader*>(query);
        uint16_t queryId = ntohs(header->id);
        uint16_t qdcount = ntohs(header->qdcount);

        std::cout << "MinimalDnsServer: Query ID: " << queryId << ", QDCOUNT: " << qdcount << std::endl;
        
        // Debug: Print the raw query data
        std::cout << "MinimalDnsServer: Raw query data (" << queryLen << " bytes): ";
        for (size_t i = 0; i < std::min(queryLen, (size_t)64); ++i) {
            printf("%02x ", query[i]);
        }
        std::cout << std::endl;
        std::cout.flush();

        if (qdcount == 0) {
            std::cout << "MinimalDnsServer: No questions in query, returning" << std::endl;
            std::cout.flush();
            return; 
        }
        
        if (qdcount > 1) {
            std::cout << "MinimalDnsServer: Multiple questions (" << qdcount << "), handling first one only" << std::endl;
            std::cout.flush();
        }

        // Parse question name
        std::string queryName = parseDnsName(query + sizeof(DnsHeader), queryLen - sizeof(DnsHeader));
        
        // Create response
        std::vector<uint8_t> response;
        
        // Copy original query as response header
        response.resize(queryLen);
        memcpy(response.data(), query, queryLen);
        
        // Modify header for response
        DnsHeader* respHeader = reinterpret_cast<DnsHeader*>(response.data());
        respHeader->flags = htons(0x8180); // Response, recursion available
        respHeader->ancount = htons(0);
        respHeader->qdcount = htons(qdcount); // Keep original question count
        
        std::cout << "MinimalDnsServer: Query for domain: '" << queryName << "'" << std::endl;
        
        // Look up dummy record
        std::cout << "MinimalDnsServer: Looking up record for '" << queryName << "'" << std::endl;
        for (const auto& record : testRecords_) {
            std::cout << "MinimalDnsServer: Available record: '" << record.first << "' -> '" << record.second << "'" << std::endl;
        }
        std::cout.flush();
        
        auto it = testRecords_.find(queryName);
        if (it != testRecords_.end()) {
            std::cout << "MinimalDnsServer: Found record for " << queryName << " -> " << it->second << std::endl;
            // Add answer section - provide answer only for A record query
            respHeader->ancount = htons(1);
            
            // Answer: compressed name pointer (0xC00C) - points to first occurrence of domain name
            response.push_back(0xC0);
            response.push_back(0x0C);
            
            // Type A (0x0001) - IPv4 address record
            response.push_back(0x00);
            response.push_back(0x01);
            
            // Class IN (0x0001) 
            response.push_back(0x00);
            response.push_back(0x01);
            
            // TTL (300 seconds)
            response.push_back(0x00);
            response.push_back(0x00);
            response.push_back(0x01);
            response.push_back(0x2C);
            
            // Data length (4 bytes for IPv4)
            response.push_back(0x00);
            response.push_back(0x04);
            
            // IP address - first resize then write
            response.resize(response.size() + 4);
            inet_aton(it->second.c_str(), reinterpret_cast<in_addr*>(&response[response.size() - 4]));
        } else {
            std::cout << "MinimalDnsServer: No record found for " << queryName << ", sending NXDOMAIN" << std::endl;
            respHeader->flags = htons(0x8183); // Response, recursion available, NXDOMAIN (RCODE=3)
        }

        // Send response
        ssize_t sent = sendto(sockfd_, response.data(), response.size(), 0,
                             (sockaddr*)&clientAddr, clientLen);
        std::cout << "MinimalDnsServer: Sent " << sent << " bytes response" << std::endl;
    }

    std::string parseDnsName(const uint8_t* data, size_t maxLen) {
        std::string result;
        size_t pos = 0;
        
        while (pos < maxLen) {
            uint8_t len = data[pos++];
            if (len == 0) break;
            
            if (pos + len > maxLen) break;
            
            if (!result.empty()) result += ".";
            result.append(reinterpret_cast<const char*>(data + pos), len);
            pos += len;
        }
        
        return result;
    }

public:
    MinimalDnsServer(uint16_t port = 5353) : port_(port) {}
    
    ~MinimalDnsServer() {
        stop();
    }

    bool start() {
        if (running_.exchange(true)) {
            return false; // Already running
        }
        
        serverThread_ = std::thread([this]() { serverLoop(); });
        
        // Wait a bit for server to start
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return true;
    }

    void stop() {
        if (running_.exchange(false)) {
            if (serverThread_.joinable()) {
                serverThread_.join();
            }
        }
    }

    void addRecord(const std::string& name, const std::string& ip) {
        testRecords_[name] = ip;
    }

    uint16_t getPort() const { return port_; }
};