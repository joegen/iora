// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>
#include <vector>

namespace iora {
namespace core {

// ══════════════════════════════════════════════════════════════════════════════
// BufferView — Non-owning read-only view over a contiguous byte range
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Non-owning view over a contiguous byte range, analogous to
/// std::string_view but for std::uint8_t. Enables zero-copy parsing of
/// network packets, SIP messages, RTP headers, and media frames.
class BufferView
{
public:
  static constexpr std::size_t npos = std::size_t(-1);

  /// \brief Default constructor — empty view.
  constexpr BufferView() noexcept : _data(nullptr), _size(0) {}

  /// \brief Construct from raw pointer and size.
  constexpr BufferView(const std::uint8_t* data, std::size_t size) noexcept
    : _data(data), _size(size)
  {
  }

  // ── Accessors ────────────────────────────────────────────────────────────

  constexpr const std::uint8_t* data() const noexcept { return _data; }
  constexpr std::size_t size() const noexcept { return _size; }
  constexpr bool empty() const noexcept { return _size == 0; }

  std::uint8_t operator[](std::size_t i) const
  {
    assert(i < _size && "BufferView::operator[] index out of bounds");
    return _data[i];
  }

  // ── Iterators ────────────────────────────────────────────────────────────

  constexpr const std::uint8_t* begin() const noexcept { return _data; }
  constexpr const std::uint8_t* end() const noexcept { return _data + _size; }

  // ── Slicing ──────────────────────────────────────────────────────────────

  BufferView subview(std::size_t offset, std::size_t len = npos) const noexcept
  {
    if (offset >= _size)
    {
      return {};
    }
    std::size_t maxLen = _size - offset;
    return BufferView(_data + offset, len < maxLen ? len : maxLen);
  }

  BufferView first(std::size_t n) const noexcept
  {
    return BufferView(_data, n < _size ? n : _size);
  }

  BufferView last(std::size_t n) const noexcept
  {
    if (n >= _size)
    {
      return *this;
    }
    return BufferView(_data + _size - n, n);
  }

  void removePrefix(std::size_t n) noexcept
  {
    if (n >= _size)
    {
      _data = nullptr;
      _size = 0;
    }
    else
    {
      _data += n;
      _size -= n;
    }
  }

  void removeSuffix(std::size_t n) noexcept
  {
    if (n >= _size)
    {
      _size = 0;
    }
    else
    {
      _size -= n;
    }
  }

  // ── Conversion ───────────────────────────────────────────────────────────

  /// \brief Copy into an owned vector.
  std::vector<std::uint8_t> toOwned() const
  {
    return std::vector<std::uint8_t>(_data, _data + _size);
  }

  /// \brief Reinterpret as text.
  std::string_view asStringView() const noexcept
  {
    return std::string_view(reinterpret_cast<const char*>(_data), _size);
  }

  // ── Comparison ───────────────────────────────────────────────────────────

  bool operator==(const BufferView& other) const noexcept
  {
    if (_size != other._size)
    {
      return false;
    }
    if (_size == 0)
    {
      return true;
    }
    return std::memcmp(_data, other._data, _size) == 0;
  }

  bool operator!=(const BufferView& other) const noexcept
  {
    return !(*this == other);
  }

  // ── Network Byte Order Readers (unchecked) ───────────────────────────────

  std::uint8_t readU8(std::size_t offset) const
  {
    assert(offset < _size && "BufferView::readU8 out of bounds");
    return _data[offset];
  }

  std::uint16_t readU16BE(std::size_t offset) const
  {
    assert(offset <= _size && _size - offset >= 2 && "BufferView::readU16BE out of bounds");
    return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(_data[offset]) << 8) |
       static_cast<std::uint16_t>(_data[offset + 1]));
  }

  std::uint16_t readU16LE(std::size_t offset) const
  {
    assert(offset <= _size && _size - offset >= 2 && "BufferView::readU16LE out of bounds");
    return static_cast<std::uint16_t>(
       static_cast<std::uint16_t>(_data[offset]) |
      (static_cast<std::uint16_t>(_data[offset + 1]) << 8));
  }

  std::uint32_t readU32BE(std::size_t offset) const
  {
    assert(offset <= _size && _size - offset >= 4 && "BufferView::readU32BE out of bounds");
    return (static_cast<std::uint32_t>(_data[offset])     << 24) |
           (static_cast<std::uint32_t>(_data[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(_data[offset + 2]) <<  8) |
            static_cast<std::uint32_t>(_data[offset + 3]);
  }

  std::uint32_t readU32LE(std::size_t offset) const
  {
    assert(offset <= _size && _size - offset >= 4 && "BufferView::readU32LE out of bounds");
    return  static_cast<std::uint32_t>(_data[offset]) |
           (static_cast<std::uint32_t>(_data[offset + 1]) <<  8) |
           (static_cast<std::uint32_t>(_data[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(_data[offset + 3]) << 24);
  }

  std::uint64_t readU64BE(std::size_t offset) const
  {
    assert(offset <= _size && _size - offset >= 8 && "BufferView::readU64BE out of bounds");
    return (static_cast<std::uint64_t>(_data[offset])     << 56) |
           (static_cast<std::uint64_t>(_data[offset + 1]) << 48) |
           (static_cast<std::uint64_t>(_data[offset + 2]) << 40) |
           (static_cast<std::uint64_t>(_data[offset + 3]) << 32) |
           (static_cast<std::uint64_t>(_data[offset + 4]) << 24) |
           (static_cast<std::uint64_t>(_data[offset + 5]) << 16) |
           (static_cast<std::uint64_t>(_data[offset + 6]) <<  8) |
            static_cast<std::uint64_t>(_data[offset + 7]);
  }

  std::uint64_t readU64LE(std::size_t offset) const
  {
    assert(offset <= _size && _size - offset >= 8 && "BufferView::readU64LE out of bounds");
    return  static_cast<std::uint64_t>(_data[offset]) |
           (static_cast<std::uint64_t>(_data[offset + 1]) <<  8) |
           (static_cast<std::uint64_t>(_data[offset + 2]) << 16) |
           (static_cast<std::uint64_t>(_data[offset + 3]) << 24) |
           (static_cast<std::uint64_t>(_data[offset + 4]) << 32) |
           (static_cast<std::uint64_t>(_data[offset + 5]) << 40) |
           (static_cast<std::uint64_t>(_data[offset + 6]) << 48) |
           (static_cast<std::uint64_t>(_data[offset + 7]) << 56);
  }

  // ── Network Byte Order Readers (checked — for untrusted input) ───────────

  std::optional<std::uint8_t> readU8Checked(std::size_t offset) const noexcept
  {
    if (offset >= _size)
    {
      return std::nullopt;
    }
    return _data[offset];
  }

  std::optional<std::uint16_t> readU16BEChecked(std::size_t offset) const noexcept
  {
    if (offset > _size || _size - offset < 2)
    {
      return std::nullopt;
    }
    return readU16BE(offset);
  }

  std::optional<std::uint16_t> readU16LEChecked(std::size_t offset) const noexcept
  {
    if (offset > _size || _size - offset < 2)
    {
      return std::nullopt;
    }
    return readU16LE(offset);
  }

  std::optional<std::uint32_t> readU32BEChecked(std::size_t offset) const noexcept
  {
    if (offset > _size || _size - offset < 4)
    {
      return std::nullopt;
    }
    return readU32BE(offset);
  }

  std::optional<std::uint32_t> readU32LEChecked(std::size_t offset) const noexcept
  {
    if (offset > _size || _size - offset < 4)
    {
      return std::nullopt;
    }
    return readU32LE(offset);
  }

  std::optional<std::uint64_t> readU64BEChecked(std::size_t offset) const noexcept
  {
    if (offset > _size || _size - offset < 8)
    {
      return std::nullopt;
    }
    return readU64BE(offset);
  }

  std::optional<std::uint64_t> readU64LEChecked(std::size_t offset) const noexcept
  {
    if (offset > _size || _size - offset < 8)
    {
      return std::nullopt;
    }
    return readU64LE(offset);
  }

private:
  const std::uint8_t* _data;
  std::size_t _size;
};

// ══════════════════════════════════════════════════════════════════════════════
// BufferWriter — Cursor-based writer into a pre-allocated byte buffer
// ══════════════════════════════════════════════════════════════════════════════

/// \brief Cursor-based writer into a pre-allocated buffer. Advances a write
/// position on each operation. All write methods return false on overflow
/// without modifying the buffer.
class BufferWriter
{
public:
  BufferWriter(std::uint8_t* data, std::size_t capacity) noexcept
    : _data(data), _capacity(capacity), _pos(0)
  {
  }

  // ── Write Methods (return false on overflow) ─────────────────────────────

  bool writeU8(std::uint8_t value)
  {
    if (remaining() < 1)
    {
      return false;
    }
    _data[_pos++] = value;
    return true;
  }

  bool writeU16BE(std::uint16_t value)
  {
    if (remaining() < 2)
    {
      return false;
    }
    _data[_pos++] = static_cast<std::uint8_t>(value >> 8);
    _data[_pos++] = static_cast<std::uint8_t>(value);
    return true;
  }

  bool writeU16LE(std::uint16_t value)
  {
    if (remaining() < 2)
    {
      return false;
    }
    _data[_pos++] = static_cast<std::uint8_t>(value);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 8);
    return true;
  }

  bool writeU32BE(std::uint32_t value)
  {
    if (remaining() < 4)
    {
      return false;
    }
    _data[_pos++] = static_cast<std::uint8_t>(value >> 24);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 16);
    _data[_pos++] = static_cast<std::uint8_t>(value >>  8);
    _data[_pos++] = static_cast<std::uint8_t>(value);
    return true;
  }

  bool writeU32LE(std::uint32_t value)
  {
    if (remaining() < 4)
    {
      return false;
    }
    _data[_pos++] = static_cast<std::uint8_t>(value);
    _data[_pos++] = static_cast<std::uint8_t>(value >>  8);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 16);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 24);
    return true;
  }

  bool writeU64BE(std::uint64_t value)
  {
    if (remaining() < 8)
    {
      return false;
    }
    _data[_pos++] = static_cast<std::uint8_t>(value >> 56);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 48);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 40);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 32);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 24);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 16);
    _data[_pos++] = static_cast<std::uint8_t>(value >>  8);
    _data[_pos++] = static_cast<std::uint8_t>(value);
    return true;
  }

  bool writeU64LE(std::uint64_t value)
  {
    if (remaining() < 8)
    {
      return false;
    }
    _data[_pos++] = static_cast<std::uint8_t>(value);
    _data[_pos++] = static_cast<std::uint8_t>(value >>  8);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 16);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 24);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 32);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 40);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 48);
    _data[_pos++] = static_cast<std::uint8_t>(value >> 56);
    return true;
  }

  bool append(BufferView data)
  {
    return append(data.data(), data.size());
  }

  bool append(const std::uint8_t* data, std::size_t len)
  {
    if (remaining() < len)
    {
      return false;
    }
    std::memcpy(_data + _pos, data, len);
    _pos += len;
    return true;
  }

  // ── Query Methods ────────────────────────────────────────────────────────

  std::size_t bytesWritten() const noexcept { return _pos; }
  std::size_t remaining() const noexcept { return _capacity - _pos; }

  /// \brief Returns a BufferView over the bytes written so far.
  BufferView written() const noexcept
  {
    return BufferView(_data, _pos);
  }

private:
  std::uint8_t* _data;
  std::size_t _capacity;
  std::size_t _pos;
};

} // namespace core
} // namespace iora
