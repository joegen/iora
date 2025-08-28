#include "include/iora/network/dns/dns_message.hpp"
#include <iostream>
#include <vector>

using namespace iora::network::dns;

int main() {
    // Test case from the failing test
    std::vector<std::uint8_t> maliciousMessage = {
        // DNS Header (12 bytes)
        0x12, 0x34,  // Query ID
        0x81, 0x80,  // Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0
        0x00, 0x01,  // QDCOUNT=1
        0x00, 0x01,  // ANCOUNT=1  
        0x00, 0x00,  // NSCOUNT=0
        0x00, 0x00,  // ARCOUNT=0
        
        // Question section: "test.com" A IN
        0x04, 't', 'e', 's', 't',  // label "test"
        0x03, 'c', 'o', 'm',       // label "com"
        0x00,                      // null terminator
        0x00, 0x01,               // QTYPE=A
        0x00, 0x01,               // QCLASS=IN
        
        // Answer section with compression pointer loop
        0xc0, 0x0c,               // NAME: pointer to offset 12 (question name)
        0x00, 0x01,               // TYPE=A
        0x00, 0x01,               // CLASS=IN
        0x00, 0x00, 0x0e, 0x10,   // TTL=3600
        0x00, 0x04,               // RDLENGTH=4
        
        // RDATA with pointer loop: points back to itself
        0xc0, 0x20,               // Pointer to offset 32 (points to this very pointer!)
        0x00, 0x00                // Padding to make RDLENGTH=4
    };
    
    try {
        auto result = DnsMessage::parse(maliciousMessage);
        std::cout << "Parse succeeded - no exception thrown!" << std::endl;
        return 1;
    } catch (const DnsParseException& e) {
        std::cout << "Parse failed with exception: " << e.what() << std::endl;
        return 0;
    }
}