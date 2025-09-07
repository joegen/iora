// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#pragma once

#include "dns_types.hpp"
#include "iora/core/logger.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace iora
{
namespace network
{
namespace dns
{

/// \brief DNS parsing exceptions
class DnsParseException : public std::runtime_error
{
public:
  explicit DnsParseException(const std::string &message)
      : std::runtime_error("DNS Parse Error: " + message)
  {
  }
};

/// \brief DNS message parsing and construction utilities
class DnsMessage
{
public:
  /// \brief Parse DNS message from binary data
  /// \param data Binary DNS message data
  /// \param size Size of the data
  /// \return Parsed DNS result structure
  /// \throws DnsParseException on parsing errors
  static DnsResult parse(const std::uint8_t *data, std::size_t size);

  /// \brief Parse DNS message from vector
  /// \param data Binary DNS message data
  /// \return Parsed DNS result structure
  /// \throws DnsParseException on parsing errors
  static DnsResult parse(const std::vector<std::uint8_t> &data)
  {
    return parse(data.data(), data.size());
  }

  /// \brief Build DNS query message
  /// \param question DNS question to query
  /// \param id Query identifier (0 = auto-generate)
  /// \return Binary DNS query message
  static std::vector<std::uint8_t> buildQuery(const DnsQuestion &question, std::uint16_t id = 0);

  /// \brief Build DNS query for multiple questions
  /// \param questions DNS questions to query
  /// \param id Query identifier (0 = auto-generate)
  /// \return Binary DNS query message
  static std::vector<std::uint8_t> buildQuery(const std::vector<DnsQuestion> &questions,
                                              std::uint16_t id = 0);

  /// \brief Build DNS query with configurable recursion flag
  /// \param questions DNS questions to query
  /// \param recursionDesired Whether to set RD flag (recursion desired)
  /// \param id Query identifier (0 = auto-generate)
  /// \return Binary DNS query message
  static std::vector<std::uint8_t> buildQuery(const std::vector<DnsQuestion> &questions,
                                              bool recursionDesired, std::uint16_t id = 0);

  /// \brief Generate random query ID
  static std::uint16_t generateQueryId();

  /// \brief Convert domain name to DNS wire format
  /// \param name Domain name (e.g., "example.com")
  /// \return Wire format name with length prefixes
  static std::vector<std::uint8_t> encodeName(const std::string &name);

  /// \brief Parse domain name from DNS wire format
  /// \param data DNS message data
  /// \param offset Current offset in data
  /// \param size Total data size
  /// \param name Output parameter for parsed name
  /// \return New offset after parsing name
  /// \throws DnsParseException on parsing errors
  static std::size_t decodeName(const std::uint8_t *data, std::size_t offset, std::size_t size,
                                std::string &name);

  /// \brief Parse domain name with loop detection
  /// \param data DNS message data
  /// \param offset Current offset in data
  /// \param size Total data size
  /// \param name Output parameter for parsed name
  /// \param visitedPointers Set to track visited compression pointers
  /// \return New offset after parsing name
  static std::size_t
  decodeNameWithLoopDetection(const std::uint8_t *data, std::size_t offset, std::size_t size,
                              std::string &name,
                              std::unordered_set<std::uint16_t> &visitedPointers);

private:
  /// \brief Parse DNS header from binary data
  static std::size_t parseHeader(const std::uint8_t *data, std::size_t offset, std::size_t size,
                                 DnsHeader &header);

  /// \brief Parse DNS question from binary data
  static std::size_t parseQuestion(const std::uint8_t *data, std::size_t offset, std::size_t size,
                                   DnsQuestion &question);

  /// \brief Parse DNS resource record from binary data
  static std::size_t parseResourceRecord(const std::uint8_t *data, std::size_t offset,
                                         std::size_t size, DnsResourceRecord &rr);

  /// \brief Parse DNS resource record with RDATA offset tracking
  static std::size_t parseResourceRecord(const std::uint8_t *data, std::size_t offset,
                                         std::size_t size, DnsResourceRecord &rr,
                                         std::size_t &rdataOffset);

  /// \brief Parse specific record types from resource record data
  static void parseTypedRecord(const DnsResourceRecord &rr, DnsResult &result,
                               const std::uint8_t *messageData, std::size_t messageSize,
                               std::size_t rdataOffset);

  /// \brief Security validation for RDATA to detect malicious compression pointers
  /// \param rr Resource record to validate
  /// \throws DnsParseException if malicious compression patterns are detected
  static void validateRdataSecurity(const DnsResourceRecord &rr);

  /// \brief Parse A record data
  static ARecord parseARecord(const DnsResourceRecord &rr);

  /// \brief Parse AAAA record data
  static AAAARecord parseAAAARecord(const DnsResourceRecord &rr);

  /// \brief Parse SRV record data (critical for SIP)
  static SrvRecord parseSrvRecord(const DnsResourceRecord &rr, const std::uint8_t *messageData,
                                  std::size_t messageSize, std::size_t rdataOffset);

  /// \brief Parse NAPTR record data (essential for SIP)
  static NaptrRecord parseNaptrRecord(const DnsResourceRecord &rr, const std::uint8_t *messageData,
                                      std::size_t messageSize, std::size_t rdataOffset);

  /// \brief Parse CNAME record data
  static CnameRecord parseCnameRecord(const DnsResourceRecord &rr, const std::uint8_t *messageData,
                                      std::size_t messageSize, std::size_t rdataOffset);

  /// \brief Parse MX record data
  static MxRecord parseMxRecord(const DnsResourceRecord &rr, const std::uint8_t *messageData,
                                std::size_t messageSize, std::size_t rdataOffset);

  /// \brief Parse TXT record data
  static TxtRecord parseTxtRecord(const DnsResourceRecord &rr);

  /// \brief Parse PTR record data
  static PtrRecord parsePtrRecord(const DnsResourceRecord &rr, const std::uint8_t *messageData,
                                  std::size_t messageSize, std::size_t rdataOffset);

  /// \brief Parse SOA record data (Start of Authority, RFC 1035)
  static SoaRecord parseSoaRecord(const DnsResourceRecord &rr, const std::uint8_t *messageData,
                                  std::size_t messageSize, std::size_t rdataOffset);

  /// \brief Parse domain name from RDATA with compression support
  ///
  /// This is a complex function that handles various edge cases including:
  /// - Compression pointers within RDATA pointing back to message
  /// - Mixed compression/literal name segments
  /// - Pointer loops (prevented by visited set in decodeName)
  /// - Names that extend beyond RDATA bounds via compression
  /// - Invalid compression pointers beyond message bounds
  ///
  /// Critical test cases needed:
  /// - Simple name in RDATA without compression
  /// - Name with compression pointer at start of RDATA
  /// - Name with compression pointer in middle of name
  /// - Multiple compression pointers in sequence
  /// - Pointer loop detection (should throw exception)
  /// - Pointer beyond message bounds (should throw exception)
  /// - Empty RDATA (should handle gracefully)
  /// - RDATA smaller than pointer (2 bytes)
  ///
  /// \param messageData Full DNS message data
  /// \param messageSize Size of full message
  /// \param rdataStart Absolute offset where RDATA starts in message
  /// \param rdataOffset Offset within RDATA where name starts
  /// \param rdata RDATA buffer
  /// \param rdataSize Size of RDATA
  /// \param name Output parameter for parsed name
  /// \return New offset within RDATA after parsing name
  static std::size_t decodeNameFromRdata(const std::uint8_t *messageData, std::size_t messageSize,
                                         std::size_t rdataStart, std::size_t rdataOffset,
                                         const std::uint8_t *rdata, std::size_t rdataSize,
                                         std::string &name);

  /// \brief Write 16-bit value to buffer in network byte order
  static void writeUint16(std::vector<std::uint8_t> &buffer, std::uint16_t value);

  /// \brief Write 32-bit value to buffer in network byte order
  static void writeUint32(std::vector<std::uint8_t> &buffer, std::uint32_t value);

  /// \brief Read 16-bit value from buffer in network byte order
  static std::uint16_t readUint16(const std::uint8_t *data, std::size_t offset);

  /// \brief Read 32-bit value from buffer in network byte order
  static std::uint32_t readUint32(const std::uint8_t *data, std::size_t offset);

  /// \brief Check if there's enough data at offset
  static void checkBounds(std::size_t offset, std::size_t needed, std::size_t total);

  /// \brief Static random number generator for query IDs
  static std::random_device &getRandomDevice();
  static std::mt19937 &getRandomGenerator();
};

// ==================== Implementation ====================

inline std::uint16_t DnsMessage::generateQueryId()
{
  static std::uniform_int_distribution<std::uint16_t> dist(1, 65535);
  return dist(getRandomGenerator());
}

inline std::random_device &DnsMessage::getRandomDevice()
{
  static std::random_device rd;
  return rd;
}

inline std::mt19937 &DnsMessage::getRandomGenerator()
{
  static std::mt19937 gen(getRandomDevice()());
  return gen;
}

inline void DnsMessage::writeUint16(std::vector<std::uint8_t> &buffer, std::uint16_t value)
{
  std::uint16_t netValue = htons(value);
  const std::uint8_t *bytes = reinterpret_cast<const std::uint8_t *>(&netValue);
  buffer.insert(buffer.end(), bytes, bytes + 2);
}

inline void DnsMessage::writeUint32(std::vector<std::uint8_t> &buffer, std::uint32_t value)
{
  std::uint32_t netValue = htonl(value);
  const std::uint8_t *bytes = reinterpret_cast<const std::uint8_t *>(&netValue);
  buffer.insert(buffer.end(), bytes, bytes + 4);
}

inline std::uint16_t DnsMessage::readUint16(const std::uint8_t *data, std::size_t offset)
{
  std::uint16_t netValue;
  std::memcpy(&netValue, data + offset, 2);
  return ntohs(netValue);
}

inline std::uint32_t DnsMessage::readUint32(const std::uint8_t *data, std::size_t offset)
{
  std::uint32_t netValue;
  std::memcpy(&netValue, data + offset, 4);
  return ntohl(netValue);
}

inline void DnsMessage::checkBounds(std::size_t offset, std::size_t needed, std::size_t total)
{
  if (offset + needed > total)
  {
    throw DnsParseException("Insufficient data at offset " + std::to_string(offset) + ", needed " +
                            std::to_string(needed) + ", total " + std::to_string(total));
  }
}

inline std::vector<std::uint8_t> DnsMessage::encodeName(const std::string &name)
{
  std::vector<std::uint8_t> encoded;

  if (name.empty() || name == ".")
  {
    encoded.push_back(0); // Root domain
    return encoded;
  }

  std::istringstream iss(name);
  std::string label;

  while (std::getline(iss, label, '.'))
  {
    if (label.empty())
      continue;

    if (label.length() > constants::DNS_MAX_LABEL_SIZE)
    {
      throw DnsParseException("Label too long: " + label + " (max " +
                              std::to_string(constants::DNS_MAX_LABEL_SIZE) + ")");
    }

    encoded.push_back(static_cast<std::uint8_t>(label.length()));
    encoded.insert(encoded.end(), label.begin(), label.end());
  }

  encoded.push_back(0); // Null terminator

  if (encoded.size() > constants::DNS_MAX_NAME_SIZE)
  {
    throw DnsParseException("Domain name too long: " + name);
  }

  return encoded;
}

inline std::vector<std::uint8_t> DnsMessage::buildQuery(const DnsQuestion &question,
                                                        std::uint16_t id)
{
  return buildQuery(std::vector<DnsQuestion>{question}, id);
}

inline std::vector<std::uint8_t> DnsMessage::buildQuery(const std::vector<DnsQuestion> &questions,
                                                        std::uint16_t id)
{
  // Default behavior: recursion desired = true (backward compatibility)
  return buildQuery(questions, true, id);
}

inline std::vector<std::uint8_t> DnsMessage::buildQuery(const std::vector<DnsQuestion> &questions,
                                                        bool recursionDesired, std::uint16_t id)
{
  std::vector<std::uint8_t> message;
  message.reserve(512); // Typical UDP DNS message size

  // Generate ID if not provided
  if (id == 0)
  {
    id = generateQueryId();
  }

  // DNS Header with configurable recursion flag
  writeUint16(message, id);                                 // Query ID
  std::uint16_t flags = recursionDesired ? 0x0100 : 0x0000; // Standard query, RD configurable
  writeUint16(message, flags);
  writeUint16(message, static_cast<std::uint16_t>(questions.size())); // QDCOUNT
  writeUint16(message, 0);                                            // ANCOUNT
  writeUint16(message, 0);                                            // NSCOUNT
  writeUint16(message, 0);                                            // ARCOUNT

  // Questions section
  for (const auto &question : questions)
  {
    // QNAME
    auto encodedName = encodeName(question.qname);
    message.insert(message.end(), encodedName.begin(), encodedName.end());

    // QTYPE
    writeUint16(message, static_cast<std::uint16_t>(question.qtype));

    // QCLASS
    writeUint16(message, static_cast<std::uint16_t>(question.qclass));
  }

  return message;
}

inline DnsResult DnsMessage::parse(const std::uint8_t *data, std::size_t size)
{
  if (size < constants::DNS_HEADER_SIZE)
  {
    throw DnsParseException("Message too short for DNS header: " + std::to_string(size) +
                            " bytes, minimum " + std::to_string(constants::DNS_HEADER_SIZE) +
                            " required");
  }

  DnsResult result;
  std::size_t offset = 0;

  // Parse header
  offset = parseHeader(data, offset, size, result.header);

  // Parse questions
  result.questions.reserve(result.header.qdcount);
  for (std::uint16_t i = 0; i < result.header.qdcount; ++i)
  {
    DnsQuestion question;
    offset = parseQuestion(data, offset, size, question);
    result.questions.push_back(question);
  }

  // Parse answers
  result.answers.reserve(result.header.ancount);
  for (std::uint16_t i = 0; i < result.header.ancount; ++i)
  {
    DnsResourceRecord rr;
    std::size_t rdataOffset;
    offset = parseResourceRecord(data, offset, size, rr, rdataOffset);
    result.answers.push_back(rr);
    parseTypedRecord(rr, result, data, size, rdataOffset);
  }

  // Parse authority records
  result.authority.reserve(result.header.nscount);
  for (std::uint16_t i = 0; i < result.header.nscount; ++i)
  {
    DnsResourceRecord rr;
    std::size_t rdataOffset;
    offset = parseResourceRecord(data, offset, size, rr, rdataOffset);
    result.authority.push_back(rr);
    // Parse authority records into typed records (essential for SOA negative caching per RFC 2308)
    parseTypedRecord(rr, result, data, size, rdataOffset);
  }

  // Parse additional records
  result.additional.reserve(result.header.arcount);
  for (std::uint16_t i = 0; i < result.header.arcount; ++i)
  {
    DnsResourceRecord rr;
    std::size_t rdataOffset;
    offset = parseResourceRecord(data, offset, size, rr, rdataOffset);
    result.additional.push_back(rr);
    // Parse additional records into typed records as they often contain useful data
    parseTypedRecord(rr, result, data, size, rdataOffset);
  }

  return result;
}

inline std::size_t DnsMessage::parseHeader(const std::uint8_t *data, std::size_t offset,
                                           std::size_t size, DnsHeader &header)
{
  checkBounds(offset, constants::DNS_HEADER_SIZE, size);

  header.id = readUint16(data, offset);
  offset += 2;

  std::uint16_t flags = readUint16(data, offset);
  header.qr = (flags & 0x8000) != 0;
  header.opcode = static_cast<DnsOpcode>((flags >> 11) & 0x0F);
  header.aa = (flags & 0x0400) != 0;
  header.tc = (flags & 0x0200) != 0;
  header.rd = (flags & 0x0100) != 0;
  header.ra = (flags & 0x0080) != 0;
  header.z = static_cast<std::uint8_t>((flags >> 4) & 0x07);
  header.rcode = static_cast<DnsResponseCode>(flags & 0x0F);
  offset += 2;

  header.qdcount = readUint16(data, offset);
  offset += 2;
  header.ancount = readUint16(data, offset);
  offset += 2;
  header.nscount = readUint16(data, offset);
  offset += 2;
  header.arcount = readUint16(data, offset);
  offset += 2;

  return offset;
}

inline std::size_t DnsMessage::parseQuestion(const std::uint8_t *data, std::size_t offset,
                                             std::size_t size, DnsQuestion &question)
{
  // Parse QNAME
  offset = decodeName(data, offset, size, question.qname);

  // Parse QTYPE
  checkBounds(offset, 2, size);
  question.qtype = static_cast<DnsType>(readUint16(data, offset));
  offset += 2;

  // Parse QCLASS
  checkBounds(offset, 2, size);
  question.qclass = static_cast<DnsClass>(readUint16(data, offset));
  offset += 2;

  return offset;
}

inline std::size_t DnsMessage::parseResourceRecord(const std::uint8_t *data, std::size_t offset,
                                                   std::size_t size, DnsResourceRecord &rr)
{
  // Parse NAME
  offset = decodeName(data, offset, size, rr.name);

  // Parse TYPE
  checkBounds(offset, 2, size);
  rr.type = static_cast<DnsType>(readUint16(data, offset));
  offset += 2;

  // Parse CLASS
  checkBounds(offset, 2, size);
  rr.cls = static_cast<DnsClass>(readUint16(data, offset));
  offset += 2;

  // Parse TTL
  checkBounds(offset, 4, size);
  rr.ttl = readUint32(data, offset);
  offset += 4;

  // Parse RDLENGTH
  checkBounds(offset, 2, size);
  rr.rdlength = readUint16(data, offset);
  offset += 2;

  // Parse RDATA
  checkBounds(offset, rr.rdlength, size);
  rr.rdata.assign(data + offset, data + offset + rr.rdlength);

  // Security validation: detect malicious compression pointers in RDATA where they shouldn't exist
  validateRdataSecurity(rr);

  offset += rr.rdlength;

  return offset;
}

inline std::size_t DnsMessage::parseResourceRecord(const std::uint8_t *data, std::size_t offset,
                                                   std::size_t size, DnsResourceRecord &rr,
                                                   std::size_t &rdataOffset)
{
  // Parse NAME
  offset = decodeName(data, offset, size, rr.name);

  // Parse TYPE
  checkBounds(offset, 2, size);
  rr.type = static_cast<DnsType>(readUint16(data, offset));
  offset += 2;

  // Parse CLASS
  checkBounds(offset, 2, size);
  rr.cls = static_cast<DnsClass>(readUint16(data, offset));
  offset += 2;

  // Parse TTL
  checkBounds(offset, 4, size);
  rr.ttl = readUint32(data, offset);
  offset += 4;

  // Parse RDLENGTH
  checkBounds(offset, 2, size);
  rr.rdlength = readUint16(data, offset);
  offset += 2;

  // Store RDATA start offset
  rdataOffset = offset;

  // Parse RDATA
  checkBounds(offset, rr.rdlength, size);
  rr.rdata.assign(data + offset, data + offset + rr.rdlength);

  // Security validation: detect malicious compression pointers in RDATA where they shouldn't exist
  validateRdataSecurity(rr);

  offset += rr.rdlength;

  return offset;
}

inline std::size_t DnsMessage::decodeName(const std::uint8_t *data, std::size_t offset,
                                          std::size_t size, std::string &name)
{
  std::unordered_set<std::uint16_t> visitedPointers;
  return decodeNameWithLoopDetection(data, offset, size, name, visitedPointers);
}

inline std::size_t
DnsMessage::decodeNameWithLoopDetection(const std::uint8_t *data, std::size_t offset,
                                        std::size_t size, std::string &name,
                                        std::unordered_set<std::uint16_t> &visitedPointers)
{
  name.clear();
  std::size_t originalOffset = offset;
  bool jumped = false;
  std::size_t totalLength = 0;

  while (offset < size)
  {
    std::uint8_t length = data[offset];

    // Check for compression
    if ((length & constants::DNS_COMPRESSION_MASK) == constants::DNS_COMPRESSION_MASK)
    {
      if (!jumped)
      {
        originalOffset = offset + 2; // Continue from after the pointer
        jumped = true;
      }

      checkBounds(offset, 2, size);
      std::uint16_t pointer = readUint16(data, offset) & constants::DNS_COMPRESSION_POINTER_MASK;

      // Check for invalid pointer
      if (pointer >= size)
      {
        throw DnsParseException("Invalid compression pointer: " + std::to_string(pointer) +
                                ", message size: " + std::to_string(size));
      }

      // Check for compression loops
      if (visitedPointers.find(pointer) != visitedPointers.end())
      {
        throw DnsParseException("Compression pointer loop detected at offset: " +
                                std::to_string(pointer));
      }
      visitedPointers.insert(pointer);

      offset = pointer;
      continue;
    }

    // End of name
    if (length == 0)
    {
      offset++;
      break;
    }

    // Regular label
    if (length > constants::DNS_MAX_LABEL_SIZE)
    {
      throw DnsParseException("Label too long: " + std::to_string(length) + " (max " +
                              std::to_string(constants::DNS_MAX_LABEL_SIZE) + ")");
    }

    checkBounds(offset + 1, length, size);

    if (!name.empty())
    {
      name += ".";
    }

    name.append(reinterpret_cast<const char *>(data + offset + 1), length);
    offset += length + 1;

    totalLength += length + 1;
    if (totalLength > constants::DNS_MAX_NAME_SIZE)
    {
      throw DnsParseException("Domain name too long: " + std::to_string(totalLength) + " (max " +
                              std::to_string(constants::DNS_MAX_NAME_SIZE) + ")");
    }
  }

  return jumped ? originalOffset : offset;
}

inline std::size_t DnsMessage::decodeNameFromRdata(const std::uint8_t *messageData,
                                                   std::size_t messageSize, std::size_t rdataStart,
                                                   std::size_t rdataOffset,
                                                   const std::uint8_t *rdata, std::size_t rdataSize,
                                                   std::string &name)
{
  // Handle edge case: empty RDATA or invalid offset
  if (rdataSize == 0 || rdataOffset >= rdataSize)
  {
    name.clear();
    return rdataOffset;
  }

  // Check if we have a compression pointer at this offset in RDATA
  if (rdataOffset + 1 < rdataSize)
  {
    std::uint8_t firstByte = rdata[rdataOffset];
    if ((firstByte & constants::DNS_COMPRESSION_MASK) == constants::DNS_COMPRESSION_MASK)
    {
      // Edge case: ensure we have enough bytes for a compression pointer
      if (rdataOffset + 2 > rdataSize)
      {
        throw DnsParseException("RDATA too short for compression pointer at offset " +
                                std::to_string(rdataOffset));
      }

      // This is a compression pointer - decode directly from message
      //
      // CRITICAL: The pointer bytes in RDATA represent an absolute offset into the full DNS
      // message, not relative to RDATA. The readUint16() call correctly handles network byte order
      // (ntohs). This works correctly even if pointer bytes are split across TCP fragmentation
      // boundaries because RDATA is already assembled as a contiguous buffer by
      // parseResourceRecord().
      //
      // Edge cases handled:
      // - Pointer near message-size boundary (checked below)
      // - Big-endian vs host byte order (readUint16 handles ntohs conversion)
      // - Pointer beyond message bounds (validation below)
      std::uint16_t pointer =
        readUint16(rdata, rdataOffset) & constants::DNS_COMPRESSION_POINTER_MASK;

      // Validate pointer is within message bounds with safety margin for name parsing
      if (static_cast<std::size_t>(pointer) < messageSize &&
          (static_cast<std::size_t>(pointer) + 1) <
            messageSize) // Need at least 1 byte for length field
      {
        decodeName(messageData, pointer, messageSize, name);
        return rdataOffset + 2; // Compression pointer is 2 bytes
      }
      else
      {
        throw DnsParseException("Invalid compression pointer in RDATA: " + std::to_string(pointer) +
                                " (message size=" + std::to_string(messageSize) +
                                ", need at least 1 byte for name length)");
      }
    }
  }

  // Not a compression pointer, parse name directly from RDATA
  // But we need to handle the case where the name itself contains compression pointers
  // by translating RDATA offsets to absolute message offsets
  std::size_t absoluteOffset = rdataStart + rdataOffset;

  // Validate absolute offset is within message bounds
  if (absoluteOffset >= messageSize)
  {
    throw DnsParseException("RDATA name offset beyond message bounds: " +
                            std::to_string(absoluteOffset) + " >= " + std::to_string(messageSize));
  }

  std::size_t newOffset = decodeName(messageData, absoluteOffset, messageSize, name);

  // Convert back to relative RDATA offset
  // If decodeName followed a compression pointer, it returns the original offset + pointer size
  // If it parsed a regular name, it returns the new absolute offset
  if (newOffset >= rdataStart && newOffset <= rdataStart + rdataSize)
  {
    return newOffset - rdataStart;
  }
  else
  {
    // Name parsing went beyond RDATA bounds or followed compression pointer
    // Find how many bytes were consumed in the original RDATA
    std::size_t consumedInRdata = rdataOffset;
    while (consumedInRdata < rdataSize &&
           (rdata[consumedInRdata] & constants::DNS_COMPRESSION_MASK) !=
             constants::DNS_COMPRESSION_MASK &&
           rdata[consumedInRdata] != 0)
    {
      std::uint8_t labelLen = rdata[consumedInRdata];
      if (labelLen > constants::DNS_MAX_LABEL_SIZE)
      {
        throw DnsParseException("Invalid label length in RDATA: " + std::to_string(labelLen));
      }
      consumedInRdata += 1 + labelLen;
      if (consumedInRdata >= rdataSize)
      {
        throw DnsParseException("Name extends beyond RDATA bounds");
      }
    }

    // Account for terminator or compression pointer
    if (consumedInRdata < rdataSize)
    {
      if ((rdata[consumedInRdata] & constants::DNS_COMPRESSION_MASK) ==
          constants::DNS_COMPRESSION_MASK)
      {
        consumedInRdata += 2; // Compression pointer
      }
      else if (rdata[consumedInRdata] == 0)
      {
        consumedInRdata += 1; // Null terminator
      }
    }

    return consumedInRdata;
  }
}

inline void DnsMessage::parseTypedRecord(const DnsResourceRecord &rr, DnsResult &result,
                                         const std::uint8_t *messageData, std::size_t messageSize,
                                         std::size_t rdataOffset)
{
  try
  {
    switch (rr.type)
    {
    case DnsType::A:
      result.a_records.push_back(parseARecord(rr));
      break;
    case DnsType::AAAA:
      result.aaaa_records.push_back(parseAAAARecord(rr));
      break;
    case DnsType::SRV:
      result.srv_records.push_back(parseSrvRecord(rr, messageData, messageSize, rdataOffset));
      break;
    case DnsType::NAPTR:
      result.naptr_records.push_back(parseNaptrRecord(rr, messageData, messageSize, rdataOffset));
      break;
    case DnsType::CNAME:
      result.cname_records.push_back(parseCnameRecord(rr, messageData, messageSize, rdataOffset));
      break;
    case DnsType::MX:
      result.mx_records.push_back(parseMxRecord(rr, messageData, messageSize, rdataOffset));
      break;
    case DnsType::TXT:
      result.txt_records.push_back(parseTxtRecord(rr));
      break;
    case DnsType::PTR:
      result.ptr_records.push_back(parsePtrRecord(rr, messageData, messageSize, rdataOffset));
      break;
    case DnsType::SOA:
      result.soa_records.push_back(parseSoaRecord(rr, messageData, messageSize, rdataOffset));
      break;
    default:
      // Unknown record type - keep in generic records
      break;
    }
  }
  catch (const std::exception &e)
  {
    // Log parsing error but don't fail entire message
    iora::core::Logger::warning("DNS record parsing error for " + rr.name + " type=" +
                                std::to_string(static_cast<uint16_t>(rr.type)) + ": " + e.what());
  }
}

inline ARecord DnsMessage::parseARecord(const DnsResourceRecord &rr)
{
  if (rr.rdata.size() != 4)
  {
    throw DnsParseException("Invalid A record data length");
  }

  ARecord record(rr.name, "", rr.ttl);

  std::ostringstream oss;
  oss << static_cast<int>(rr.rdata[0]) << "." << static_cast<int>(rr.rdata[1]) << "."
      << static_cast<int>(rr.rdata[2]) << "." << static_cast<int>(rr.rdata[3]);

  record.address = oss.str();
  return record;
}

inline AAAARecord DnsMessage::parseAAAARecord(const DnsResourceRecord &rr)
{
  if (rr.rdata.size() != 16)
  {
    throw DnsParseException("Invalid AAAA record data length");
  }

  AAAARecord record(rr.name, "", rr.ttl);

  // Use proper IPv6 canonical formatting with zero-compression
  char ipv6Str[INET6_ADDRSTRLEN];
  struct in6_addr addr;
  std::memcpy(&addr, rr.rdata.data(), 16);

  if (inet_ntop(AF_INET6, &addr, ipv6Str, INET6_ADDRSTRLEN) != nullptr)
  {
    record.address = std::string(ipv6Str);
  }
  else
  {
    // Fallback to manual formatting if inet_ntop fails
    std::ostringstream oss;
    for (int i = 0; i < 8; ++i)
    {
      if (i > 0)
        oss << ":";
      std::uint16_t segment = (rr.rdata[i * 2] << 8) | rr.rdata[i * 2 + 1];
      oss << std::hex << std::setw(4) << std::setfill('0') << segment;
    }
    record.address = oss.str();
  }

  return record;
}

inline SrvRecord DnsMessage::parseSrvRecord(const DnsResourceRecord &rr,
                                            const std::uint8_t *messageData,
                                            std::size_t messageSize, std::size_t rdataOffset)
{
  if (rr.rdata.size() < 6)
  {
    throw DnsParseException("Invalid SRV record data length");
  }

  SrvRecord record(rr.name, 0, 0, 0, "", rr.ttl);

  record.priority = readUint16(rr.rdata.data(), 0);
  record.weight = readUint16(rr.rdata.data(), 2);
  record.port = readUint16(rr.rdata.data(), 4);

  // Parse target name with proper compression support
  if (messageData != nullptr && messageSize > 0)
  {
    std::size_t nameOffset = 6; // Target name starts after priority(2) + weight(2) + port(2)
    if (nameOffset < rr.rdata.size())
    {
      decodeNameFromRdata(messageData, messageSize, rdataOffset, nameOffset, rr.rdata.data(),
                          rr.rdata.size(), record.target);
    }
  }

  return record;
}

inline NaptrRecord DnsMessage::parseNaptrRecord(const DnsResourceRecord &rr,
                                                const std::uint8_t *messageData,
                                                std::size_t messageSize, std::size_t rdataOffset)
{
  if (rr.rdata.size() < 4)
  {
    throw DnsParseException("Invalid NAPTR record data length");
  }

  NaptrRecord record(rr.name, 0, 0, "", "", "", "", rr.ttl);

  std::size_t offset = 0;

  record.order = readUint16(rr.rdata.data(), offset);
  offset += 2;
  record.preference = readUint16(rr.rdata.data(), offset);
  offset += 2;

  // Parse strings: flags, service, regexp, replacement
  auto parseString = [&](std::string &str)
  {
    if (offset >= rr.rdata.size())
      return;
    std::uint8_t len = rr.rdata[offset++];
    if (offset + len > rr.rdata.size())
      return;
    str.assign(reinterpret_cast<const char *>(rr.rdata.data() + offset), len);
    offset += len;
  };

  parseString(record.flags);
  parseString(record.service);
  parseString(record.regexp);

  // Parse replacement domain name with proper compression support
  if (offset < rr.rdata.size() && messageData != nullptr && messageSize > 0)
  {
    decodeNameFromRdata(messageData, messageSize, rdataOffset, offset, rr.rdata.data(),
                        rr.rdata.size(), record.replacement);
  }

  return record;
}

inline CnameRecord DnsMessage::parseCnameRecord(const DnsResourceRecord &rr,
                                                const std::uint8_t *messageData,
                                                std::size_t messageSize, std::size_t rdataOffset)
{
  CnameRecord record(rr.name, "", rr.ttl);

  // Parse CNAME with proper compression support
  if (!rr.rdata.empty() && messageData != nullptr && messageSize > 0)
  {
    decodeNameFromRdata(messageData, messageSize, rdataOffset, 0, rr.rdata.data(), rr.rdata.size(),
                        record.cname);
  }

  return record;
}

inline MxRecord DnsMessage::parseMxRecord(const DnsResourceRecord &rr,
                                          const std::uint8_t *messageData, std::size_t messageSize,
                                          std::size_t rdataOffset)
{
  if (rr.rdata.size() < 2)
  {
    throw DnsParseException("Invalid MX record data length");
  }

  MxRecord record(rr.name, 0, "", rr.ttl);

  record.preference = readUint16(rr.rdata.data(), 0);

  // Parse exchange name with proper compression support
  if (rr.rdata.size() > 2 && messageData != nullptr && messageSize > 0)
  {
    std::size_t nameOffset = 2; // Exchange name starts after preference(2)
    decodeNameFromRdata(messageData, messageSize, rdataOffset, nameOffset, rr.rdata.data(),
                        rr.rdata.size(), record.exchange);
  }

  return record;
}

inline TxtRecord DnsMessage::parseTxtRecord(const DnsResourceRecord &rr)
{
  TxtRecord record(rr.name, {}, rr.ttl);

  std::size_t offset = 0;
  while (offset < rr.rdata.size())
  {
    std::uint8_t len = rr.rdata[offset++];
    if (offset + len > rr.rdata.size())
      break;

    std::string text(reinterpret_cast<const char *>(rr.rdata.data() + offset), len);
    record.text.push_back(text);
    offset += len;
  }

  return record;
}

inline PtrRecord DnsMessage::parsePtrRecord(const DnsResourceRecord &rr,
                                            const std::uint8_t *messageData,
                                            std::size_t messageSize, std::size_t rdataOffset)
{
  PtrRecord record(rr.name, "", rr.ttl);

  // Parse PTR domain name with proper compression support
  if (!rr.rdata.empty() && messageData != nullptr && messageSize > 0)
  {
    decodeNameFromRdata(messageData, messageSize, rdataOffset, 0, rr.rdata.data(), rr.rdata.size(),
                        record.ptrdname);
  }

  return record;
}

inline SoaRecord DnsMessage::parseSoaRecord(const DnsResourceRecord &rr,
                                            const std::uint8_t *messageData,
                                            std::size_t messageSize, std::size_t rdataOffset)
{
  // SOA records require at least 20 bytes (2 names minimum + 5 * 4-byte integers)
  if (rr.rdata.size() < 20)
  {
    throw DnsParseException("Invalid SOA record data length");
  }

  SoaRecord record(rr.name, "", "", 0, 0, 0, 0, 0, rr.ttl);

  std::size_t offset = 0;

  // Parse MNAME (primary nameserver) with compression support
  if (messageData != nullptr && messageSize > 0)
  {
    offset = decodeNameFromRdata(messageData, messageSize, rdataOffset, offset, rr.rdata.data(),
                                 rr.rdata.size(), record.mname);
  }
  else
  {
    throw DnsParseException("SOA parsing requires full message context for compression");
  }

  // Parse RNAME (responsible person email) with compression support
  if (offset < rr.rdata.size())
  {
    offset = decodeNameFromRdata(messageData, messageSize, rdataOffset, offset, rr.rdata.data(),
                                 rr.rdata.size(), record.rname);
  }

  // Parse 5 32-bit integers: SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
  if (offset + 20 > rr.rdata.size())
  {
    throw DnsParseException("SOA record truncated: insufficient data for numeric fields");
  }

  record.serial = readUint32(rr.rdata.data(), offset);
  offset += 4;
  record.refresh = readUint32(rr.rdata.data(), offset);
  offset += 4;
  record.retry = readUint32(rr.rdata.data(), offset);
  offset += 4;
  record.expire = readUint32(rr.rdata.data(), offset);
  offset += 4;
  record.minimum = readUint32(rr.rdata.data(), offset);

  return record;
}

inline void DnsMessage::validateRdataSecurity(const DnsResourceRecord &rr)
{
  // Validate A records for malicious compression pointers and wrong lengths
  if (rr.type == DnsType::A)
  {
    // A records must have exactly 4 bytes of RDATA (IP address)
    // If they have wrong length AND contain compression pointer patterns, it's malicious
    if (rr.rdata.size() != 4)
    {
      // Check if the wrong-length RDATA contains compression pointers (definitely malicious)
      if (rr.rdata.size() >= 2 &&
          (rr.rdata[0] & constants::DNS_COMPRESSION_MASK) == constants::DNS_COMPRESSION_MASK)
      {
        throw DnsParseException(
          "Malicious compression pointer in A record RDATA with invalid length");
      }
      // If no compression pointer pattern, let normal parsing handle the length error
    }
    else
    {
      // For correctly-sized A records, check for compression pointers disguised as IP addresses
      if ((rr.rdata[0] & constants::DNS_COMPRESSION_MASK) == constants::DNS_COMPRESSION_MASK)
      {
        std::uint16_t pointer = ((rr.rdata[0] & 0x3F) << 8) | rr.rdata[1];

        // Additional check: if the remaining bytes are 0x00, 0x00, it's likely padding for a
        // pointer
        if (pointer < 64 && rr.rdata[2] == 0x00 && rr.rdata[3] == 0x00)
        {
          throw DnsParseException("Malicious compression pointer detected in A record RDATA");
        }
      }
    }
  }

  // Validate other record types that should never contain compression pointers in RDATA
  if (rr.type == DnsType::TXT || rr.type == DnsType::AAAA)
  {
    for (std::size_t i = 0; i < rr.rdata.size() - 1; ++i)
    {
      if ((rr.rdata[i] & constants::DNS_COMPRESSION_MASK) == constants::DNS_COMPRESSION_MASK)
      {
        throw DnsParseException("Malicious compression pointer detected in " +
                                std::to_string(static_cast<std::uint16_t>(rr.type)) +
                                " record RDATA at offset " + std::to_string(i));
      }
    }
  }

  // Additional validation for other record types that shouldn't have compression pointers
  // in specific parts of their RDATA could be added here in the future
}

} // namespace dns
} // namespace network
} // namespace iora