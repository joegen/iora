#pragma once

/// \file sockaddr_utils.hpp
/// \brief Conversion between POSIX sockaddr_storage and iora::network::TransportAddress.
///
/// addressFromSockaddr is the ONE implementation of the sockaddr -> address
/// direction. It previously existed as a private static in BOTH
/// detail/tcp_engine.hpp and detail/udp_engine.hpp (byte-for-byte identical);
/// because both were private, a third consumer (iora_media's RTP transport
/// binding) could not reach either and copied it again. Lifting it here retired
/// all three copies: both engines now forward to it.
///
/// toSockaddr is the shared implementation of the OPPOSITE direction, but it has
/// not yet displaced the in-library sockaddr-building code: TcpEngine still
/// builds sockaddrs inline on its listen and connect paths, where the conversion
/// is interleaved with family-dependent socket creation and (on connect)
/// hostname resolution, which this function deliberately does not do. Its
/// consumers today are outside this library. Do not read "the one
/// implementation" as covering this direction until those sites are converted.
///
/// Lives in its own header rather than in ip_utils.hpp so that the low-level IP
/// parsing utilities do not have to depend on transport_types.hpp (a layering
/// inversion); this header sits above both and depends on each.

#include "iora/network/ip_utils.hpp"
#include "iora/network/transport_types.hpp"

#include <cstdint>
#include <cstring>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace iora
{
namespace network
{

/// \brief Render a sockaddr_storage as a TransportAddress (host literal + port).
/// \return the address; a default-constructed (empty host, port 0) value for a
///         family other than AF_INET/AF_INET6, or if the host literal cannot be
///         rendered.
inline TransportAddress addressFromSockaddr(const sockaddr_storage &ss)
{
  TransportAddress addr;
  char host[NI_MAXHOST]{};
  if (ss.ss_family == AF_INET)
  {
    const auto *sa4 = reinterpret_cast<const sockaddr_in *>(&ss);
    if (::inet_ntop(AF_INET, &sa4->sin_addr, host, sizeof(host)) != nullptr)
    {
      addr.host = host;
    }
    addr.port = ntohs(sa4->sin_port);
  }
  else if (ss.ss_family == AF_INET6)
  {
    const auto *sa6 = reinterpret_cast<const sockaddr_in6 *>(&ss);
    if (::inet_ntop(AF_INET6, &sa6->sin6_addr, host, sizeof(host)) != nullptr)
    {
      addr.host = host;
    }
    addr.port = ntohs(sa6->sin6_port);
  }
  return addr;
}

/// \brief Build a sockaddr_storage from a TransportAddress.
///
/// Uses the ALREADY-PARSED value held by IpAddress rather than re-rendering it
/// to a string for inet_pton: a parse -> toString() -> re-parse round-trip costs
/// an extra parse plus a heap allocation on every call (this runs per datagram
/// on a media TX path) and adds failure legs that cannot fire.
///
/// \param out zeroed and filled on success; untouched-but-zeroed on failure.
/// \param outLen set to sizeof(sockaddr_in) or sizeof(sockaddr_in6) on success.
/// \return false if \p addr.host is not a valid IP literal (this does NOT
///         resolve hostnames).
inline bool toSockaddr(const TransportAddress &addr, sockaddr_storage &out,
                       socklen_t &outLen)
{
  std::memset(&out, 0, sizeof(out));
  outLen = 0;
  IpAddress ip(addr.host);
  if (!ip.isValid())
  {
    return false;
  }
  if (ip.family() == AddressFamily::IPv4)
  {
    auto *sa4 = reinterpret_cast<sockaddr_in *>(&out);
    sa4->sin_family = AF_INET;
    sa4->sin_port = htons(addr.port);
    // IpAddress::ipv4() is the HOST-order 32-bit value (IPv4::toString shifts
    // >> 24 for the leading octet), so htonl() yields network order.
    sa4->sin_addr.s_addr = htonl(ip.ipv4());
    outLen = sizeof(sockaddr_in);
    return true;
  }
  auto *sa6 = reinterpret_cast<sockaddr_in6 *>(&out);
  sa6->sin6_family = AF_INET6;
  sa6->sin6_port = htons(addr.port);
  // IPv6::Address is a 16-byte array already in network order.
  std::memcpy(&sa6->sin6_addr, ip.ipv6().data(), ip.ipv6().size());
  outLen = sizeof(sockaddr_in6);
  return true;
}

/// \brief Apply a DSCP mark to a socket fd.
///
/// The socket family is determined via getsockname (works on a freshly-created,
/// not-yet-connected socket too — the AF is set at socket() time). The DSCP value
/// occupies the high 6 bits of the 8-bit TOS / IPv6 traffic-class byte
/// (val = dscp << 2).
///
/// This was a byte-identical private static in BOTH detail/tcp_engine.hpp and
/// detail/udp_engine.hpp — the same duplicate-copy anti-pattern already retired
/// for addressFromSockaddr. Lifting it here retires both copies: each engine now
/// forwards to it (CF-L1). Shared by the per-session setDscp() API and the
/// at-creation application of config.dscpValue.
///
/// \return true on success; false if \p fd is negative, getsockname fails, or the
///         setsockopt fails.
inline bool applyDscpToFd(int fd, std::uint8_t dscp)
{
  if (fd < 0)
  {
    return false;
  }
  sockaddr_storage ss{};
  socklen_t sl = sizeof(ss);
  if (::getsockname(fd, reinterpret_cast<sockaddr *>(&ss), &sl) != 0)
  {
    return false;
  }
  int val = static_cast<int>(dscp) << 2;
  if (ss.ss_family == AF_INET6)
  {
    // On a dual-stack AF_INET6 socket carrying an IPv4-mapped peer
    // (::ffff:a.b.c.d), many kernels govern the egress IPv4 TOS byte via IP_TOS
    // rather than IPV6_TCLASS, so a v6-only mark can be silently dropped for the
    // mapped-IPv4 SIP signaling path this targets. Set IPV6_TCLASS as the
    // family-primary option, then best-effort mirror the mark onto IP_TOS for
    // the mapped-IPv4 egress. Some kernels reject IP_TOS on AF_INET6 — that
    // secondary failure is ignored; success is decided by the primary option.
    if (::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &val, sizeof(val)) != 0)
    {
      return false;
    }
    (void)::setsockopt(fd, IPPROTO_IP, IP_TOS, &val, sizeof(val));
    return true;
  }
  return ::setsockopt(fd, IPPROTO_IP, IP_TOS, &val, sizeof(val)) == 0;
}

} // namespace network
} // namespace iora
