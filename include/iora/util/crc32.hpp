// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace iora
{
namespace util
{

/// \brief Table-driven, incremental CRC-32 (reflected polynomial 0xEDB88320).
///
/// This is the CRC-32 used by the gzip trailer (RFC 1952 §2.3.1) and by
/// zlib/PNG: reflected input/output, initial value 0xFFFFFFFF, final XOR
/// 0xFFFFFFFF. CRC-32 of empty input is 0x00000000.
///
/// A shared low-level utility (not a cryptographic primitive — CRC provides no
/// security property, hence util/ rather than crypto/). It accepts raw bytes
/// (std::string_view / ptr+len), never a vector<uint8_t>, so it is binary-safe
/// over embedded NULs. The incremental accumulator lets the streaming/file gzip
/// encoder fold the CRC over chunks without materializing the whole input.
class Crc32
{
private:
  /// Build the 256-entry lookup table for the reflected polynomial 0xEDB88320
  /// at compile time. Declared before its use (as util/base64.hpp declares
  /// makeRevTable before decode()) so the function-local `static constexpr`
  /// table in update() sees a complete definition.
  static constexpr std::array<std::uint32_t, 256> makeTable()
  {
    std::array<std::uint32_t, 256> t{};
    for (std::uint32_t n = 0; n < 256; ++n)
    {
      std::uint32_t c = n;
      for (int k = 0; k < 8; ++k)
      {
        c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      }
      t[n] = c;
    }
    return t;
  }

public:
  /// \brief CRC-32 over a byte view (binary-safe; embedded NULs preserved).
  static std::uint32_t compute(std::string_view data)
  {
    return compute(data.data(), data.size());
  }

  /// \brief CRC-32 over a raw byte range. \p data may be null iff \p len is 0.
  static std::uint32_t compute(const void *data, std::size_t len)
  {
    Incremental acc;
    acc.update(data, len);
    return acc.value();
  }

  /// \brief Incremental CRC-32 accumulator: feed bytes in arbitrary chunks,
  /// read the running CRC with value() at any point. There is deliberately no
  /// reset() — one accumulator computes one CRC (one gzip member).
  struct Incremental
  {
    /// \brief Fold \p len bytes at \p data into the running CRC.
    void update(const void *data, std::size_t len)
    {
      // The lookup table for the reflected polynomial 0xEDB88320, built once at
      // compile time and defined at its point of use (as util/base64.hpp does
      // with its function-local kTable). One shared instance across every
      // translation unit that includes this header.
      static constexpr std::array<std::uint32_t, 256> kTable = makeTable();
      // Index the table with unsigned char: a signed char sign-extends bytes
      // >= 0x80 and corrupts the CRC across the whole high-byte domain.
      const auto *p = static_cast<const unsigned char *>(data);
      std::uint32_t crc = _crc;
      for (std::size_t i = 0; i < len; ++i)
      {
        crc = kTable[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
      }
      _crc = crc;
    }

    /// \brief Fold a byte view into the running CRC (binary-safe).
    void update(std::string_view data) { update(data.data(), data.size()); }

    /// \brief The current CRC-32. Non-mutating: applies the final complement to
    /// a copy of the running state, so it can be read mid-stream and update()
    /// may continue afterwards.
    std::uint32_t value() const { return _crc ^ 0xFFFFFFFFu; }

  private:
    std::uint32_t _crc = 0xFFFFFFFFu;
  };
};

} // namespace util
} // namespace iora
