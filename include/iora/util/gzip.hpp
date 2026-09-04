// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#pragma once

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "iora/core/result.hpp"
#include "iora/util/crc32.hpp"

namespace iora
{
namespace util
{

/// \brief Internal RFC 1951 DEFLATE core. Not part of the public surface — only
/// the RFC 1952 gzip container (Gzip::compress / Gzip::Encoder) is exposed. The
/// core takes primitive knobs (an integer search depth, a byte XFL) and knows
/// nothing about the public Gzip::Level enum.
namespace detail
{

// DEFLATE / LZ77 constants (RFC 1951).
constexpr int GZIP_WSIZE = 32768;      ///< Max back-reference distance.
constexpr int GZIP_WMASK = GZIP_WSIZE - 1;
constexpr int GZIP_MIN_MATCH = 3;
constexpr int GZIP_MAX_MATCH = 258;
constexpr int GZIP_HASH_BITS = 15;
constexpr int GZIP_HASH_SIZE = 1 << GZIP_HASH_BITS;
constexpr int GZIP_HASH_MASK = GZIP_HASH_SIZE - 1;
constexpr int GZIP_END_OF_BLOCK = 256; ///< Fixed-Huffman EOB symbol.
/// Streaming block segment size: the incremental encoder flushes one
/// fixed-Huffman block per this many bytes of pending input. Independent of how
/// the caller chunks update(), so streaming output depends only on content.
constexpr std::size_t GZIP_STREAM_SEGMENT = 32768;

// Length codes (RFC 1951 §3.2.5): symbol = 257 + index; base length + extra
// bits per index. Length 258 is the special last code (index 28, 0 extra bits).
constexpr int kLengthBase[29] = {3,   4,   5,   6,   7,   8,   9,   10,  11,  13,
                                 15,  17,  19,  23,  27,  31,  35,  43,  51,  59,
                                 67,  83,  99,  115, 131, 163, 195, 227, 258};
constexpr int kLengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                  2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};

// Distance codes (RFC 1951 §3.2.5): symbol = index; base distance + extra bits.
constexpr int kDistBase[30] = {1,    2,    3,    4,     5,     7,     9,    13,
                               17,   25,   33,   49,    65,    97,    129,  193,
                               257,  385,  513,  769,   1025,  1537,  2049, 3073,
                               4097, 6145, 8193, 12289, 16385, 24577};
constexpr int kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4,  4,  5,  5,  6,
                                6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

/// LSB-first bit writer. DEFLATE packs bits into bytes starting with the least
/// significant bit; a byte is appended to the buffer as soon as 8 bits
/// accumulate, so the buffer always holds only complete bytes and the partial
/// tail lives in the bit accumulator (this is what lets the streaming encoder
/// hand out completed bytes between blocks without disturbing the bit stream).
class BitWriter
{
public:
  /// Write the low \p count bits of \p value, least-significant bit first.
  void putBits(std::uint32_t value, int count)
  {
    _bitBuf |= (static_cast<std::uint64_t>(value) << _bitCount);
    _bitCount += count;
    while (_bitCount >= 8)
    {
      _out.push_back(static_cast<char>(_bitBuf & 0xFFu));
      _bitBuf >>= 8;
      _bitCount -= 8;
    }
  }

  /// Pad the current partial byte with zero bits to a byte boundary. Called
  /// only once, before the gzip trailer (never between DEFLATE blocks).
  void alignToByte()
  {
    if (_bitCount > 0)
    {
      _out.push_back(static_cast<char>(_bitBuf & 0xFFu));
      _bitBuf = 0;
      _bitCount = 0;
    }
  }

  /// Move out the complete bytes produced so far, leaving any partial bits in
  /// the accumulator so the bit stream continues seamlessly into the next
  /// block. Used by the streaming encoder between blocks.
  std::string takeCompletedBytes()
  {
    std::string done = std::move(_out);
    _out.clear();
    return done;
  }

  const std::string &buffer() const { return _out; }

private:
  std::string _out;
  std::uint64_t _bitBuf = 0;
  int _bitCount = 0;
};

/// Reverse the low \p len bits of \p code (Huffman codes are transmitted MSB
/// first, but the writer emits LSB first — so a reversed code emitted LSB-first
/// reproduces the canonical MSB-first bit order).
inline std::uint32_t reverseBits(std::uint32_t code, int len)
{
  std::uint32_t r = 0;
  for (int i = 0; i < len; ++i)
  {
    r = (r << 1) | (code & 1u);
    code >>= 1;
  }
  return r;
}

/// Assign canonical Huffman codes (MSB-first) from per-symbol code lengths,
/// per RFC 1951 §3.2.2.
inline std::vector<std::uint32_t> canonicalCodes(const std::vector<int> &lengths)
{
  int maxBits = 0;
  for (int l : lengths)
  {
    if (l > maxBits)
    {
      maxBits = l;
    }
  }
  std::vector<int> blCount(static_cast<std::size_t>(maxBits) + 1, 0);
  for (int l : lengths)
  {
    if (l > 0)
    {
      ++blCount[static_cast<std::size_t>(l)];
    }
  }
  std::vector<std::uint32_t> nextCode(static_cast<std::size_t>(maxBits) + 1, 0);
  std::uint32_t code = 0;
  for (int bits = 1; bits <= maxBits; ++bits)
  {
    code = (code + static_cast<std::uint32_t>(blCount[static_cast<std::size_t>(bits) - 1])) << 1;
    nextCode[static_cast<std::size_t>(bits)] = code;
  }
  std::vector<std::uint32_t> codes(lengths.size(), 0);
  for (std::size_t i = 0; i < lengths.size(); ++i)
  {
    int len = lengths[i];
    if (len > 0)
    {
      codes[i] = nextCode[static_cast<std::size_t>(len)]++;
    }
  }
  return codes;
}

/// The per-symbol code lengths of the fixed-Huffman literal/length alphabet
/// (RFC 1951 §3.2.6): 0-143 -> 8, 144-255 -> 9, 256-279 -> 7, 280-287 -> 8.
inline std::vector<int> fixedLitLengths()
{
  std::vector<int> litLens(288);
  for (int i = 0; i <= 143; ++i) { litLens[static_cast<std::size_t>(i)] = 8; }
  for (int i = 144; i <= 255; ++i) { litLens[static_cast<std::size_t>(i)] = 9; }
  for (int i = 256; i <= 279; ++i) { litLens[static_cast<std::size_t>(i)] = 7; }
  for (int i = 280; i <= 287; ++i) { litLens[static_cast<std::size_t>(i)] = 8; }
  return litLens;
}

/// The fixed-Huffman code tables (RFC 1951 §3.2.6), pre-reversed for LSB-first
/// emission. Built once at first use.
struct FixedHuff
{
  std::array<std::uint16_t, 288> litCode{};
  std::array<std::uint8_t, 288> litLen{};
  std::array<std::uint16_t, 30> distCode{};
  std::array<std::uint8_t, 30> distLen{};
};

inline const FixedHuff &fixedHuff()
{
  static const FixedHuff h = []() {
    FixedHuff t;
    std::vector<int> litLens = fixedLitLengths();
    auto lc = canonicalCodes(litLens);
    for (int i = 0; i < 288; ++i)
    {
      t.litLen[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(litLens[static_cast<std::size_t>(i)]);
      t.litCode[static_cast<std::size_t>(i)] =
        static_cast<std::uint16_t>(reverseBits(lc[static_cast<std::size_t>(i)], litLens[static_cast<std::size_t>(i)]));
    }
    std::vector<int> distLens(30, 5);
    auto dc = canonicalCodes(distLens);
    for (int i = 0; i < 30; ++i)
    {
      t.distLen[static_cast<std::size_t>(i)] = 5;
      t.distCode[static_cast<std::size_t>(i)] =
        static_cast<std::uint16_t>(reverseBits(dc[static_cast<std::size_t>(i)], 5));
    }
    return t;
  }();
  return h;
}

/// Emit a literal/length or EOB symbol using the fixed-Huffman table.
inline void emitSymbol(BitWriter &bw, const FixedHuff &h, int sym)
{
  bw.putBits(h.litCode[static_cast<std::size_t>(sym)], h.litLen[static_cast<std::size_t>(sym)]);
}

/// Emit an LZ77 match of \p length (3..258) at back-distance \p dist (1..32768).
inline void emitMatch(BitWriter &bw, const FixedHuff &h, int length, int dist)
{
  // Length symbol + extra bits.
  int li = 28;
  while (li > 0 && kLengthBase[li] > length)
  {
    --li;
  }
  emitSymbol(bw, h, 257 + li);
  if (kLengthExtra[li] > 0)
  {
    bw.putBits(static_cast<std::uint32_t>(length - kLengthBase[li]), kLengthExtra[li]);
  }
  // Distance symbol + extra bits.
  int di = 29;
  while (di > 0 && kDistBase[di] > dist)
  {
    --di;
  }
  bw.putBits(h.distCode[static_cast<std::size_t>(di)], h.distLen[static_cast<std::size_t>(di)]);
  if (kDistExtra[di] > 0)
  {
    bw.putBits(static_cast<std::uint32_t>(dist - kDistBase[di]), kDistExtra[di]);
  }
}

inline int hash3(const unsigned char *p)
{
  return ((static_cast<int>(p[0]) << 10) ^ (static_cast<int>(p[1]) << 5) ^
          static_cast<int>(p[2])) &
         GZIP_HASH_MASK;
}

/// Reusable hash-chain scratch for the LZ77 match finder. Sized to a fixed
/// algorithmic bound (hash size + window), it is allocated ONCE per stream and
/// reset in place per block — never re-allocated per block/segment (which on a
/// large log would malloc+zero ~512KB per 32KB of input). Allocation is lazy so
/// tiny inputs that never search (see lz77Emit's short-circuit) pay nothing.
struct MatchFinder
{
  // std::ptrdiff_t (not long) so window-relative positions are 64-bit on every
  // data model, including LLP64 where `long` is 32-bit.
  std::vector<std::ptrdiff_t> head;
  std::vector<std::ptrdiff_t> prev;

  /// Ready the tables for a block: allocate on first use, else clear in place.
  void prepare()
  {
    if (head.empty())
    {
      head.assign(static_cast<std::size_t>(GZIP_HASH_SIZE), -1);
      prev.assign(static_cast<std::size_t>(GZIP_WSIZE), -1);
    }
    else
    {
      std::fill(head.begin(), head.end(), -1);
      std::fill(prev.begin(), prev.end(), -1);
    }
  }
};

/// Emit the LZ77 token stream (literals + matches) for buf[emitStart, emitEnd)
/// into \p bw, allowing back-references as far as \p histStart (which the
/// caller sets so that emitStart - histStart <= GZIP_WSIZE). Matches never read
/// past emitEnd, so this is correct for both the one-shot whole-buffer call and
/// the streaming per-segment call. Greedy matching; deterministic. \p maxChain
/// is the per-level search depth; \p mf is reusable scratch.
inline void lz77Emit(BitWriter &bw, const FixedHuff &h, const char *buf,
                     std::size_t histStart, std::size_t emitStart,
                     std::size_t emitEnd, int maxChain, MatchFinder &mf)
{
  const unsigned char *d = reinterpret_cast<const unsigned char *>(buf);

  // No position in a sub-3-byte emit region can start a match (a match needs
  // GZIP_MIN_MATCH bytes at and after it) — emit literals without touching the
  // hash tables at all.
  if (emitEnd - emitStart < static_cast<std::size_t>(GZIP_MIN_MATCH))
  {
    for (std::size_t p = emitStart; p < emitEnd; ++p)
    {
      emitSymbol(bw, h, static_cast<int>(d[p]));
    }
    return;
  }

  mf.prepare();
  std::vector<std::ptrdiff_t> &head = mf.head;
  std::vector<std::ptrdiff_t> &prev = mf.prev;

  // Insert position \p p (with its precomputed hash \p hv) as the new chain
  // head. head/prev hold positions RELATIVE to histStart; prev is indexed by
  // (rel & GZIP_WMASK) — zlib's scheme. Any candidate farther than the window
  // is rejected by the distance check below, and every emitted match is
  // byte-verified, so aliasing can only cost ratio, never correctness.
  auto insertHash = [&](std::size_t p, int hv) {
    std::ptrdiff_t rel = static_cast<std::ptrdiff_t>(p - histStart);
    prev[static_cast<std::size_t>(rel & GZIP_WMASK)] = head[static_cast<std::size_t>(hv)];
    head[static_cast<std::size_t>(hv)] = rel;
  };

  std::size_t p = histStart;
  for (; p < emitStart; ++p)
  {
    if (p + GZIP_MIN_MATCH <= emitEnd)
    {
      insertHash(p, hash3(d + p)); // prime history without emitting
    }
  }

  while (p < emitEnd)
  {
    int bestLen = 0;
    int bestDist = 0;
    int curHash = -1;
    if (p + GZIP_MIN_MATCH <= emitEnd)
    {
      curHash = hash3(d + p);
      const std::ptrdiff_t curRel = static_cast<std::ptrdiff_t>(p - histStart);
      const std::size_t maxLen =
        std::min<std::size_t>(GZIP_MAX_MATCH, emitEnd - p);
      std::ptrdiff_t cand = head[static_cast<std::size_t>(curHash)];
      int chain = maxChain;
      while (cand >= 0 && (curRel - cand) <= GZIP_WSIZE && chain-- > 0)
      {
        const std::size_t candPos = histStart + static_cast<std::size_t>(cand);
        std::size_t len = 0;
        while (len < maxLen && d[candPos + len] == d[p + len])
        {
          ++len;
        }
        if (static_cast<int>(len) > bestLen)
        {
          bestLen = static_cast<int>(len);
          bestDist = static_cast<int>(curRel - cand);
          if (len >= maxLen)
          {
            break;
          }
        }
        cand = prev[static_cast<std::size_t>(cand & GZIP_WMASK)];
      }
    }

    if (bestLen >= GZIP_MIN_MATCH)
    {
      emitMatch(bw, h, bestLen, bestDist);
      const std::size_t runEnd = p + static_cast<std::size_t>(bestLen);
      insertHash(p, curHash); // p+MIN_MATCH<=emitEnd holds (bestLen>=3), curHash valid
      ++p;
      while (p < runEnd)
      {
        if (p + GZIP_MIN_MATCH <= emitEnd)
        {
          insertHash(p, hash3(d + p));
        }
        ++p;
      }
    }
    else
    {
      emitSymbol(bw, h, static_cast<int>(d[p]));
      if (p + GZIP_MIN_MATCH <= emitEnd)
      {
        insertHash(p, curHash); // curHash was computed above for this p
      }
      ++p;
    }
  }
}

/// Emit one complete fixed-Huffman (BTYPE=01) block: 3-bit header, the LZ77
/// token stream, then the end-of-block symbol. Empty [emitStart, emitEnd)
/// yields a valid block containing only EOB (the empty-input case).
inline void emitFixedBlock(BitWriter &bw, const FixedHuff &h, const char *buf,
                           std::size_t histStart, std::size_t emitStart,
                           std::size_t emitEnd, bool bfinal, int maxChain,
                           MatchFinder &mf)
{
  bw.putBits(bfinal ? 1u : 0u, 1); // BFINAL (LSB-first)
  bw.putBits(1u, 2);               // BTYPE = 01 (fixed Huffman)
  lz77Emit(bw, h, buf, histStart, emitStart, emitEnd, maxChain, mf);
  emitSymbol(bw, h, GZIP_END_OF_BLOCK);
}

/// The 10-byte RFC 1952 gzip header. Deterministic: MTIME=0, OS=0xFF (unknown),
/// \p xfl derived from the compression level by the caller.
inline std::string gzipHeader(unsigned char xfl)
{
  std::string h;
  h.reserve(10);
  h.push_back(static_cast<char>(0x1f));
  h.push_back(static_cast<char>(0x8b));
  h.push_back(static_cast<char>(0x08)); // CM = 8 (deflate)
  h.push_back(static_cast<char>(0x00)); // FLG = 0
  for (int i = 0; i < 4; ++i)
  {
    h.push_back(static_cast<char>(0x00)); // MTIME = 0
  }
  h.push_back(static_cast<char>(xfl));
  h.push_back(static_cast<char>(0xFF)); // OS = unknown
  return h;
}

/// Append a 32-bit value little-endian (RFC 1952 §2.3.1 trailer fields).
inline void appendLE32(std::string &s, std::uint32_t v)
{
  s.push_back(static_cast<char>(v & 0xFFu));
  s.push_back(static_cast<char>((v >> 8) & 0xFFu));
  s.push_back(static_cast<char>((v >> 16) & 0xFFu));
  s.push_back(static_cast<char>((v >> 24) & 0xFFu));
}

/// Read a little-endian 16-bit value at byte offset \p pos of \p data. The
/// caller guarantees pos + 2 <= data.size() (every decode call site bounds-
/// checks first). Centralizes the byte-order assembly the decoder needs.
inline std::uint16_t readLE16(std::string_view data, std::size_t pos)
{
  return static_cast<std::uint16_t>(
    static_cast<unsigned>(static_cast<unsigned char>(data[pos])) |
    (static_cast<unsigned>(static_cast<unsigned char>(data[pos + 1])) << 8));
}

/// Read a little-endian 32-bit value at byte offset \p pos of \p data. The
/// caller guarantees pos + 4 <= data.size().
inline std::uint32_t readLE32(std::string_view data, std::size_t pos)
{
  return static_cast<std::uint32_t>(static_cast<unsigned char>(data[pos])) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(data[pos + 1]))
          << 8) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(data[pos + 2]))
          << 16) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(data[pos + 3]))
          << 24);
}

// ═══════════════════════════════════════════════════════════════════════════
// DECODER (inflate) — RFC 1951 DEFLATE body + RFC 1952 gzip container.
// One-shot, stateless, bounded: every length/offset read from the untrusted
// stream is checked, the decoded-size cap is enforced BEFORE each byte is
// materialized, and the input bit-position strictly advances within a finite
// view — so decode can never read out of bounds, over-allocate, or loop
// forever, no matter how malformed the input is.
// ═══════════════════════════════════════════════════════════════════════════

/// Internal outcome of an inflate step. The public Gzip::decompress() maps
/// MALFORMED -> DecompressError::MALFORMED_INPUT and TOO_LARGE ->
/// DecompressError::OUTPUT_TOO_LARGE.
enum class InflateStatus
{
  OK,
  MALFORMED,
  TOO_LARGE
};

/// LSB-first bit reader over a byte view — the read-side mirror of BitWriter
/// (which is write-only, so this is not duplication). DEFLATE packs bits
/// least-significant first; getBits() reassembles them in that order. The bit
/// position strictly advances and is bounded by the finite view length: a read
/// past the end sets error() and yields zeros, which every caller treats as a
/// malformed stream. This is what guarantees the decoder terminates and never
/// reads out of bounds.
class BitReader
{
public:
  explicit BitReader(std::string_view data) : _data(data) {}

  /// Read the low \p count bits (0..32), least-significant bit first. On EOF
  /// sets error() and returns the bits gathered so far (zero-extended).
  std::uint32_t getBits(int count)
  {
    std::uint32_t result = 0;
    const std::size_t totalBits = _data.size() * 8;
    for (int i = 0; i < count; ++i)
    {
      if (_bitPos >= totalBits)
      {
        _error = true;
        return result;
      }
      const std::size_t byteIdx = _bitPos >> 3;
      const int bitIdx = static_cast<int>(_bitPos & 7u);
      const std::uint32_t bit =
        (static_cast<std::uint32_t>(static_cast<unsigned char>(_data[byteIdx])) >>
         bitIdx) &
        1u;
      result |= (bit << i);
      ++_bitPos;
    }
    return result;
  }

  /// Advance to the next byte boundary, discarding up to 7 partial bits.
  void alignToByte() { _bitPos = (_bitPos + 7u) & ~static_cast<std::size_t>(7u); }

  /// Advance the position by \p n whole bytes (caller ensures byte-aligned and
  /// within bounds — used to step past a stored block after reading it raw).
  void skipBytes(std::size_t n) { _bitPos += n * 8u; }

  /// Byte offset of the current position (meaningful only when byte-aligned).
  std::size_t byteOffset() const { return _bitPos >> 3; }

  bool error() const { return _error; }
  std::size_t sizeBytes() const { return _data.size(); }
  std::string_view view() const { return _data; }
  unsigned char byteAt(std::size_t i) const
  {
    return static_cast<unsigned char>(_data[i]);
  }

private:
  std::string_view _data;
  std::size_t _bitPos = 0;
  bool _error = false;
};

/// Canonical Huffman decode table (RFC 1951 §3.2.2): count[len] = number of
/// codes of each bit length, and symbol[] holds the symbols in canonical order.
struct HuffmanTree
{
  std::array<std::uint16_t, 16> count{}; ///< indexed by code length 0..15
  std::vector<std::uint16_t> symbol;     ///< symbols in canonical (length,sym) order
};

/// Build a canonical Huffman decode table from per-symbol code \p lengths
/// (0 = unused). Reuses the same bl_count / next_code assignment scheme as the
/// encoder's detail::canonicalCodes() (RFC 1951 §3.2.2), inverted here to a
/// code->symbol table. Returns the "left" slack (zlib/puff convention):
/// 0 = complete, >0 = incomplete (code space not fully used), <0 = over-
/// subscribed (more codes than the space — always invalid). The caller decides
/// whether an incomplete code is acceptable (only the trivial single-code case
/// is, per RFC 1951 — e.g. a lone distance code).
inline int buildHuffman(HuffmanTree &tree, const std::vector<int> &lengths)
{
  tree.count.fill(0);
  for (int len : lengths)
  {
    if (len < 0 || len > 15)
    {
      return -1; // out-of-range length — treat as over-subscribed/invalid
    }
    ++tree.count[static_cast<std::size_t>(len)];
  }
  int left = 1;
  for (int len = 1; len <= 15; ++len)
  {
    left <<= 1;
    left -= static_cast<int>(tree.count[static_cast<std::size_t>(len)]);
    if (left < 0)
    {
      return left; // over-subscribed
    }
  }
  std::array<std::uint16_t, 16> offsets{};
  for (int len = 1; len < 15; ++len)
  {
    offsets[static_cast<std::size_t>(len) + 1] = static_cast<std::uint16_t>(
      offsets[static_cast<std::size_t>(len)] +
      tree.count[static_cast<std::size_t>(len)]);
  }
  tree.symbol.assign(lengths.size(), 0);
  for (std::size_t sym = 0; sym < lengths.size(); ++sym)
  {
    if (lengths[sym] != 0)
    {
      tree.symbol[offsets[static_cast<std::size_t>(lengths[sym])]++] =
        static_cast<std::uint16_t>(sym);
    }
  }
  return left;
}

/// Decode one symbol from \p br using \p tree (canonical bit-by-bit decode).
/// Returns the symbol, or -1 on an invalid code or end-of-input.
inline int huffDecode(BitReader &br, const HuffmanTree &tree)
{
  int code = 0;
  int first = 0;
  int index = 0;
  for (int len = 1; len <= 15; ++len)
  {
    code |= static_cast<int>(br.getBits(1));
    if (br.error())
    {
      return -1;
    }
    const int count = static_cast<int>(tree.count[static_cast<std::size_t>(len)]);
    if (code - count < first)
    {
      const int at = index + (code - first);
      if (at < 0 || static_cast<std::size_t>(at) >= tree.symbol.size())
      {
        return -1;
      }
      return static_cast<int>(tree.symbol[static_cast<std::size_t>(at)]);
    }
    index += count;
    first += count;
    first <<= 1;
    code <<= 1;
  }
  return -1; // ran out of code lengths without a match
}

/// The fixed-Huffman literal/length decode table (RFC 1951 §3.2.6), built once.
inline const HuffmanTree &fixedLitTree()
{
  static const HuffmanTree t = []() {
    HuffmanTree tree;
    buildHuffman(tree, fixedLitLengths());
    return tree;
  }();
  return t;
}

/// The fixed-Huffman distance decode table (30 codes, all length 5), built once.
inline const HuffmanTree &fixedDistTree()
{
  static const HuffmanTree t = []() {
    HuffmanTree tree;
    buildHuffman(tree, std::vector<int>(30, 5));
    return tree;
  }();
  return t;
}

/// Append one literal byte, enforcing the output cap in the overflow-safe
/// subtraction form (exactly maxOutputBytes is allowed; one more is TOO_LARGE).
/// Invariant on entry: out.size() <= maxOutputBytes.
inline InflateStatus emitLiteral(std::string &out, std::size_t maxOutputBytes,
                                 unsigned char value)
{
  if (static_cast<std::size_t>(1) > maxOutputBytes - out.size())
  {
    return InflateStatus::TOO_LARGE;
  }
  out.push_back(static_cast<char>(value));
  return InflateStatus::OK;
}

/// Copy an LZ77 back-reference of \p length bytes at back-distance \p dist into
/// \p out. Rejects a distance beyond the output produced so far (which would be
/// an out-of-bounds read) as MALFORMED, and enforces the output cap (overflow-
/// safe) BEFORE copying. Overlapping copies (length > dist, i.e. RLE runs) are
/// correct because each source byte is read after it has been produced. Named
/// distinctly from the encoder's emitMatch (which writes symbols to a
/// bitstream) — this is the decode-direction copy, not an emission.
inline InflateStatus copyBackref(std::string &out, std::size_t maxOutputBytes,
                                 int length, int dist)
{
  if (dist <= 0 || static_cast<std::size_t>(dist) > out.size())
  {
    return InflateStatus::MALFORMED; // distance past output start (OOB guard)
  }
  if (static_cast<std::size_t>(length) > maxOutputBytes - out.size())
  {
    return InflateStatus::TOO_LARGE;
  }
  const std::size_t src = out.size() - static_cast<std::size_t>(dist);
  for (int i = 0; i < length; ++i)
  {
    const char c = out[src + static_cast<std::size_t>(i)];
    out.push_back(c); // copy to a local first: push_back may reallocate
  }
  return InflateStatus::OK;
}

/// Decode a stored (BTYPE=00) block: byte-align, read LEN/NLEN, verify
/// NLEN == ~LEN, bounds-check LEN against the remaining input, then copy LEN raw
/// bytes — cap-checked before the copy so no more than maxOutputBytes is ever
/// materialized.
inline InflateStatus inflateStored(BitReader &br, std::string &out,
                                   std::size_t maxOutputBytes)
{
  br.alignToByte();
  std::size_t off = br.byteOffset();
  if (off + 4 > br.sizeBytes())
  {
    return InflateStatus::MALFORMED; // truncated LEN/NLEN
  }
  const unsigned len = readLE16(br.view(), off);
  const unsigned nlen = readLE16(br.view(), off + 2);
  if ((len ^ 0xFFFFu) != nlen)
  {
    return InflateStatus::MALFORMED; // one's-complement mismatch
  }
  off += 4;
  if (static_cast<std::size_t>(len) > br.sizeBytes() - off)
  {
    return InflateStatus::MALFORMED; // LEN past end of input
  }
  if (static_cast<std::size_t>(len) > maxOutputBytes - out.size())
  {
    return InflateStatus::TOO_LARGE;
  }
  for (unsigned i = 0; i < len; ++i)
  {
    out.push_back(static_cast<char>(br.byteAt(off + i)));
  }
  br.skipBytes(static_cast<std::size_t>(4) + len); // past LEN+NLEN+data
  return InflateStatus::OK;
}

/// Decode a compressed block body (shared by fixed and dynamic): a stream of
/// literal / end-of-block / (length, distance) tokens using \p litTree and
/// \p distTree, expanding length/distance symbols via the encoder's shared
/// detail::kLengthBase/kLengthExtra/kDistBase/kDistExtra tables.
inline InflateStatus inflateBlockBody(BitReader &br, std::string &out,
                                      std::size_t maxOutputBytes,
                                      const HuffmanTree &litTree,
                                      const HuffmanTree &distTree)
{
  for (;;)
  {
    const int sym = huffDecode(br, litTree);
    if (sym < 0)
    {
      return InflateStatus::MALFORMED;
    }
    if (sym < 256)
    {
      const InflateStatus s =
        emitLiteral(out, maxOutputBytes, static_cast<unsigned char>(sym));
      if (s != InflateStatus::OK)
      {
        return s;
      }
    }
    else if (sym == 256)
    {
      return InflateStatus::OK; // end of block
    }
    else
    {
      const int li = sym - 257;
      if (li >= 29)
      {
        return InflateStatus::MALFORMED; // length symbols 286/287 are invalid
      }
      int length = kLengthBase[li];
      if (kLengthExtra[li] > 0)
      {
        length += static_cast<int>(br.getBits(kLengthExtra[li]));
      }
      const int dsym = huffDecode(br, distTree);
      if (dsym < 0 || dsym >= 30)
      {
        return InflateStatus::MALFORMED; // distance symbols 30/31 are invalid
      }
      int dist = kDistBase[dsym];
      if (kDistExtra[dsym] > 0)
      {
        dist += static_cast<int>(br.getBits(kDistExtra[dsym]));
      }
      if (br.error())
      {
        return InflateStatus::MALFORMED;
      }
      const InflateStatus s = copyBackref(out, maxOutputBytes, length, dist);
      if (s != InflateStatus::OK)
      {
        return s;
      }
    }
  }
}

/// Decode a fixed-Huffman (BTYPE=01) block — the direct inverse of the encoder's
/// emitFixedBlock.
inline InflateStatus inflateFixed(BitReader &br, std::string &out,
                                  std::size_t maxOutputBytes)
{
  return inflateBlockBody(br, out, maxOutputBytes, fixedLitTree(), fixedDistTree());
}

/// Decode a dynamic-Huffman (BTYPE=10) block (RFC 1951 §3.2.7): read
/// HLIT/HDIST/HCLEN, build the code-length Huffman, RLE-decode the literal and
/// distance code lengths, reject over-subscribed / incomplete / over-running
/// tables, then decode the block body. Required because reference/gunzip streams
/// use dynamic-Huffman even though our encoder emits fixed.
inline InflateStatus inflateDynamic(BitReader &br, std::string &out,
                                    std::size_t maxOutputBytes)
{
  static constexpr int kCodeLengthOrder[19] = {16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                               11, 4,  12, 3, 13, 2, 14, 1, 15};
  const int hlit = static_cast<int>(br.getBits(5)) + 257;
  const int hdist = static_cast<int>(br.getBits(5)) + 1;
  const int hclen = static_cast<int>(br.getBits(4)) + 4;
  if (br.error())
  {
    return InflateStatus::MALFORMED;
  }
  if (hlit > 286 || hdist > 30)
  {
    return InflateStatus::MALFORMED; // 5-bit fields can encode out-of-range counts
  }
  std::vector<int> clLengths(19, 0);
  for (int i = 0; i < hclen; ++i)
  {
    clLengths[static_cast<std::size_t>(kCodeLengthOrder[i])] =
      static_cast<int>(br.getBits(3));
  }
  if (br.error())
  {
    return InflateStatus::MALFORMED;
  }
  HuffmanTree clTree;
  if (buildHuffman(clTree, clLengths) != 0)
  {
    return InflateStatus::MALFORMED; // code-length code must be complete
  }
  const int total = hlit + hdist;
  std::vector<int> lengths;
  lengths.reserve(static_cast<std::size_t>(total));
  while (static_cast<int>(lengths.size()) < total)
  {
    const int sym = huffDecode(br, clTree);
    if (sym < 0)
    {
      return InflateStatus::MALFORMED;
    }
    if (sym < 16)
    {
      lengths.push_back(sym);
      continue;
    }
    // Repeat codes 16/17/18 differ only in the value repeated and the number of
    // extra bits; the "no previous length" and over-run guards are shared.
    int value = 0;
    int repeat = 0;
    if (sym == 16)
    {
      if (lengths.empty())
      {
        return InflateStatus::MALFORMED; // repeat with no previous length
      }
      value = lengths.back();
      repeat = 3 + static_cast<int>(br.getBits(2));
    }
    else if (sym == 17)
    {
      repeat = 3 + static_cast<int>(br.getBits(3));
    }
    else if (sym == 18)
    {
      repeat = 11 + static_cast<int>(br.getBits(7));
    }
    else
    {
      return InflateStatus::MALFORMED; // code-length symbols are 0..18
    }
    if (br.error() || static_cast<int>(lengths.size()) + repeat > total)
    {
      return InflateStatus::MALFORMED; // over-run past the declared count
    }
    for (int r = 0; r < repeat; ++r)
    {
      lengths.push_back(value);
    }
  }
  // A literal or distance code is usable iff complete (left==0), or incomplete
  // only in the trivial single-code way (every symbol unused or one 1-bit code)
  // — zlib's rule; over-subscribed (left<0) is always rejected. The code-length
  // code above is held to the stricter complete-only rule and is not built here.
  const auto buildComplete = [](HuffmanTree &tree, const std::vector<int> &lens) {
    const int left = buildHuffman(tree, lens);
    if (left < 0)
    {
      return false;
    }
    return left == 0 ||
           lens.size() == static_cast<std::size_t>(tree.count[0] + tree.count[1]);
  };
  const std::vector<int> litLengths(lengths.begin(), lengths.begin() + hlit);
  const std::vector<int> distLengths(lengths.begin() + hlit, lengths.end());
  HuffmanTree litTree;
  HuffmanTree distTree;
  if (!buildComplete(litTree, litLengths) || !buildComplete(distTree, distLengths))
  {
    return InflateStatus::MALFORMED;
  }
  return inflateBlockBody(br, out, maxOutputBytes, litTree, distTree);
}

/// Drive the DEFLATE block loop until the BFINAL block completes. BTYPE=11 is
/// reserved and rejected.
inline InflateStatus inflate(BitReader &br, std::string &out,
                             std::size_t maxOutputBytes)
{
  for (;;)
  {
    const int bfinal = static_cast<int>(br.getBits(1));
    const int btype = static_cast<int>(br.getBits(2));
    if (br.error())
    {
      return InflateStatus::MALFORMED;
    }
    InflateStatus s;
    switch (btype)
    {
      case 0:
        s = inflateStored(br, out, maxOutputBytes);
        break;
      case 1:
        s = inflateFixed(br, out, maxOutputBytes);
        break;
      case 2:
        s = inflateDynamic(br, out, maxOutputBytes);
        break;
      default:
        return InflateStatus::MALFORMED; // BTYPE=11 reserved
    }
    if (s != InflateStatus::OK)
    {
      return s;
    }
    if (bfinal != 0)
    {
      return InflateStatus::OK;
    }
  }
}

/// Parse the RFC 1952 gzip header of \p input. On success returns OK and sets
/// \p dataOffset to the first DEFLATE byte. Validates magic (1f 8b) and CM=8;
/// parses-and-skips the FLG optional fields (FEXTRA/FNAME/FCOMMENT) with bounds
/// checks against attacker-controlled lengths, and VALIDATES FHCRC (the low 16
/// bits of the CRC-32 over the preceding header bytes). Reserved FLG bits 5/6/7
/// are ignored (zlib-compatible). Also requires room for the 8-byte trailer.
inline InflateStatus parseGzipHeader(std::string_view input, std::size_t &dataOffset)
{
  if (input.size() < 10)
  {
    return InflateStatus::MALFORMED; // shorter than the fixed header
  }
  const auto byteAt = [&](std::size_t i) {
    return static_cast<unsigned char>(input[i]);
  };
  if (byteAt(0) != 0x1f || byteAt(1) != 0x8b)
  {
    return InflateStatus::MALFORMED; // bad magic
  }
  if (byteAt(2) != 0x08)
  {
    return InflateStatus::MALFORMED; // CM must be 8 (deflate)
  }
  const unsigned char flg = byteAt(3);
  // bytes 4..7 MTIME, 8 XFL, 9 OS are not needed for decode.
  std::size_t pos = 10;
  const bool fhcrc = (flg & 0x02u) != 0;
  const bool fextra = (flg & 0x04u) != 0;
  const bool fname = (flg & 0x08u) != 0;
  const bool fcomment = (flg & 0x10u) != 0;
  // FLG bits 5/6/7 reserved — ignored, not rejected.
  if (fextra)
  {
    if (pos + 2 > input.size())
    {
      return InflateStatus::MALFORMED;
    }
    const std::size_t xlen = readLE16(input, pos);
    pos += 2;
    if (xlen > input.size() - pos)
    {
      return InflateStatus::MALFORMED; // XLEN over-claims remaining input
    }
    pos += xlen;
  }
  // FNAME and FCOMMENT are both NUL-terminated strings: scan to the terminator,
  // failing if none is found before end of input.
  const auto skipCString = [&](std::size_t &p) {
    while (p < input.size() && byteAt(p) != 0)
    {
      ++p;
    }
    if (p >= input.size())
    {
      return false; // no terminating NUL before end of input
    }
    ++p; // consume the NUL
    return true;
  };
  if (fname && !skipCString(pos))
  {
    return InflateStatus::MALFORMED;
  }
  if (fcomment && !skipCString(pos))
  {
    return InflateStatus::MALFORMED;
  }
  if (fhcrc)
  {
    if (pos + 2 > input.size())
    {
      return InflateStatus::MALFORMED;
    }
    const std::uint32_t headerCrc = Crc32::compute(input.substr(0, pos));
    const unsigned expected = headerCrc & 0xFFFFu;
    const unsigned stored = readLE16(input, pos);
    if (expected != stored)
    {
      return InflateStatus::MALFORMED; // header CRC mismatch
    }
    pos += 2;
  }
  if (pos + 8 > input.size())
  {
    return InflateStatus::MALFORMED; // no room for DEFLATE data + trailer
  }
  dataOffset = pos;
  return InflateStatus::OK;
}

} // namespace detail

/// \brief Native, zero-dependency gzip (RFC 1952) codec (encoder + decoder).
///
/// Encodes a complete gzip stream — a from-scratch RFC 1951 DEFLATE body
/// (fixed-Huffman blocks + hash-chain LZ77 over a <=32KB window) wrapped in the
/// RFC 1952 container with a deterministic header (MTIME=0, OS=0xFF) and a
/// CRC-32 + ISIZE trailer. Output is byte-reproducible for a given input+level
/// and decodes under any standard inflater (gunzip, zlib). Decodes any standard
/// gzip stream (stored / fixed / dynamic-Huffman blocks — including streams
/// produced by gunzip / zlib), enforcing a mandatory decoded-size cap and
/// rejecting malformed input cleanly. The raw DEFLATE core is private (namespace
/// detail); only the gzip container is exposed.
///
/// Entry points:
///   - compress(view, level): one-shot encode, materializes the whole input.
///   - Encoder: streaming/incremental encode, so a large file need not be in RAM.
///   - decompress(view, maxOutputBytes): one-shot decode of untrusted input,
///     with an incrementally-enforced output-size bound.
class Gzip
{
public:
  /// \brief Compression effort. Nested in Gzip (like core::Logger::Level) so
  /// the name says what it configures. Declared before compress() so it is in
  /// scope for the default argument. Values are ALL_UPPERCASE per the codebase
  /// constant convention. Phase-1 maps the level to the hash-chain search
  /// effort (all levels use greedy matching; lazy matching for BEST is a
  /// deferred phase-3 follow-up — the Level->finder seam is searchDepth()).
  enum class Level
  {
    FAST,
    DEFAULT,
    BEST
  };

  /// \brief Compress \p input into a complete gzip stream (one-shot). Emits a
  /// single fixed-Huffman block over the whole input.
  static std::string compress(std::string_view input, Level level = Level::DEFAULT)
  {
    std::string out = detail::gzipHeader(xflFor(level));
    detail::BitWriter bw;
    detail::MatchFinder mf;
    detail::emitFixedBlock(bw, detail::fixedHuff(), input.data(), 0, 0,
                           input.size(), true, searchDepth(level), mf);
    bw.alignToByte();
    out += bw.buffer();
    detail::appendLE32(out, Crc32::compute(input));
    detail::appendLE32(out, static_cast<std::uint32_t>(input.size() & 0xFFFFFFFFu));
    return out;
  }

  /// \brief Streaming gzip encoder: feed input in chunks via update(), then
  /// finish(). Emits ONE complete gzip member (header on first output, trailer
  /// on finish) — never raw DEFLATE. Retains a <=32KB back-reference window
  /// across chunks and folds the CRC-32/ISIZE incrementally, so peak memory
  /// does not scale with total input size.
  ///
  /// Move-only: it holds the sliding window and partial-block bit-writer state,
  /// which a copy would corrupt. Output is decode-equivalent to compress() (the
  /// same plaintext on inflate), not necessarily byte-identical (block
  /// structure legitimately differs), and is byte-stable across runs.
  class Encoder
  {
  public:
    explicit Encoder(Level level = Level::DEFAULT) : _level(level) {}

    Encoder(Encoder &&) noexcept = default;
    Encoder &operator=(Encoder &&) noexcept = default;
    Encoder(const Encoder &) = delete;
    Encoder &operator=(const Encoder &) = delete;

    /// \brief Feed a chunk of input; returns any gzip bytes produced so far
    /// (may be empty until a block is flushed).
    std::string update(std::string_view chunk)
    {
      // Debug builds abort on the contract violation; release builds must never
      // emit bytes after the trailer (that would corrupt the .gz), so a
      // post-finish() call is a safe no-op rather than silent corruption.
      assert(!_finished && "Gzip::Encoder::update() after finish()");
      if (_finished)
      {
        return {};
      }
      std::string out;
      emitHeaderIfNeeded(out);
      _crc.update(chunk);
      _isize += chunk.size();
      _buf.append(chunk.data(), chunk.size());

      const int maxChain = searchDepth(_level);
      const detail::FixedHuff &h = detail::fixedHuff();
      // Flush whole segments; leave the tail (< one segment) pending. Each
      // segment is a non-final block written into the shared, continuous bit
      // stream; only complete bytes are handed out (partial bits stay in _bw).
      while (_buf.size() - _emittedUpTo >= detail::GZIP_STREAM_SEGMENT)
      {
        const std::size_t histStart = windowStart();
        const std::size_t emitEnd = _emittedUpTo + detail::GZIP_STREAM_SEGMENT;
        detail::emitFixedBlock(_bw, h, _buf.data(), histStart, _emittedUpTo,
                               emitEnd, false, maxChain, _mf);
        _emittedUpTo = emitEnd;
        out += _bw.takeCompletedBytes();
        trimHistory();
      }
      return out;
    }

    /// \brief Flush the final block and the gzip trailer; returns the remaining
    /// gzip bytes. After finish(), the member is complete; do not call update()
    /// or finish() again.
    std::string finish()
    {
      assert(!_finished && "Gzip::Encoder::finish() called twice");
      if (_finished)
      {
        return {}; // release-safe: never emit a second trailer
      }
      std::string out;
      emitHeaderIfNeeded(out);
      const std::size_t histStart = windowStart();
      detail::emitFixedBlock(_bw, detail::fixedHuff(), _buf.data(), histStart,
                             _emittedUpTo, _buf.size(), true, searchDepth(_level),
                             _mf);
      _bw.alignToByte();
      out += _bw.takeCompletedBytes();
      detail::appendLE32(out, _crc.value());
      detail::appendLE32(out, static_cast<std::uint32_t>(_isize & 0xFFFFFFFFu));
      _finished = true;
      return out;
    }

  private:
    /// Emit the 10-byte gzip header exactly once, on whichever of update() or
    /// finish() first produces output (an empty stream emits it in finish()).
    void emitHeaderIfNeeded(std::string &out)
    {
      if (!_headerWritten)
      {
        out += detail::gzipHeader(xflFor(_level));
        _headerWritten = true;
      }
    }

    /// Absolute index where the retained 32KB back-reference window begins.
    std::size_t windowStart() const
    {
      return (_emittedUpTo > static_cast<std::size_t>(detail::GZIP_WSIZE))
               ? _emittedUpTo - static_cast<std::size_t>(detail::GZIP_WSIZE)
               : 0;
    }

    /// Drop retained history older than the 32KB window to bound memory.
    void trimHistory()
    {
      const std::size_t keepFrom = windowStart();
      if (keepFrom > 0)
      {
        _buf.erase(0, keepFrom);
        _emittedUpTo -= keepFrom;
      }
    }

    Level _level;
    bool _headerWritten = false;
    bool _finished = false;
    // Back-reference window plus not-yet-emitted input. Bytes before
    // _emittedUpTo are retained history (capped at 32KB); bytes at and after it
    // are pending segment data awaiting a block flush.
    std::string _buf;
    std::size_t _emittedUpTo = 0;
    detail::BitWriter _bw;
    detail::MatchFinder _mf; // reused across segments; no per-segment realloc
    Crc32::Incremental _crc;
    std::uint64_t _isize = 0;
  };

  /// \brief Decode failure kinds. Errors-only (success is the Result's ok
  /// channel carrying the decoded bytes). The two are distinguished so a
  /// consumer can map them to different responses (e.g. HTTP 400 vs 413).
  enum class DecompressError
  {
    MALFORMED_INPUT,  ///< structurally/integrity-invalid stream (any reason)
    OUTPUT_TOO_LARGE  ///< decoded output would exceed maxOutputBytes
  };

  /// \brief Decode a complete gzip stream (one-shot) into the original bytes.
  ///
  /// Reads a single RFC 1952 gzip member with any standard DEFLATE block type
  /// (stored / fixed / dynamic-Huffman), so it decodes streams produced by
  /// gunzip / zlib / python, not only this class's encoder. The input is
  /// treated as UNTRUSTED: \p maxOutputBytes is a mandatory hard cap enforced
  /// incrementally — decoding stops with OUTPUT_TOO_LARGE the moment the output
  /// would exceed it, so the attacker-controlled trailer ISIZE never sizes a
  /// buffer and a zip-bomb cannot exhaust memory. Any structural or integrity
  /// failure (bad magic/CM, truncation, reserved BTYPE, invalid Huffman table,
  /// back-reference past output start, CRC/ISIZE mismatch, or trailing bytes
  /// after the member) yields MALFORMED_INPUT. Never throws on malformed input,
  /// never reads out of bounds, and always terminates.
  ///
  /// \param input         a complete single-member gzip stream.
  /// \param maxOutputBytes hard upper bound on the decoded size (0 admits only
  ///                       an empty payload).
  /// \return the decoded bytes on success, or a DecompressError.
  static core::Result<std::string, DecompressError>
  decompress(std::string_view input, std::size_t maxOutputBytes)
  {
    using R = core::Result<std::string, DecompressError>;

    std::size_t dataOffset = 0;
    if (detail::parseGzipHeader(input, dataOffset) != detail::InflateStatus::OK)
    {
      return R::err(DecompressError::MALFORMED_INPUT);
    }

    // Region spanning the DEFLATE body plus the 8-byte trailer.
    const std::string_view region = input.substr(dataOffset);
    detail::BitReader br(region);
    std::string out;
    const detail::InflateStatus st = detail::inflate(br, out, maxOutputBytes);
    if (st == detail::InflateStatus::TOO_LARGE)
    {
      return R::err(DecompressError::OUTPUT_TOO_LARGE);
    }
    if (st != detail::InflateStatus::OK)
    {
      return R::err(DecompressError::MALFORMED_INPUT);
    }

    // Single member: exactly the 8-byte trailer must remain after the final
    // block — fewer means truncated, more means trailing bytes; both rejected.
    br.alignToByte();
    const std::size_t off = br.byteOffset();
    if (off + 8 != region.size())
    {
      return R::err(DecompressError::MALFORMED_INPUT);
    }

    const std::uint32_t storedCrc = detail::readLE32(region, off);
    const std::uint32_t storedIsize = detail::readLE32(region, off + 4);

    // ISIZE is verify-only (never used to size a buffer): compare to the actual
    // decoded length mod 2^32, and verify the CRC-32 of the decoded output.
    if (Crc32::compute(out) != storedCrc)
    {
      return R::err(DecompressError::MALFORMED_INPUT);
    }
    if (static_cast<std::uint32_t>(out.size() & 0xFFFFFFFFu) != storedIsize)
    {
      return R::err(DecompressError::MALFORMED_INPUT);
    }
    return R::ok(std::move(out));
  }

private:
  /// Level -> hash-chain search depth. The Level->finder seam (DQ-5): all levels
  /// use greedy matching; the level tunes only search effort. Lazy matching for
  /// BEST is a deferred phase-3 enhancement.
  static int searchDepth(Level level)
  {
    switch (level)
    {
      case Level::FAST: return 16;
      case Level::BEST: return 4096;
      case Level::DEFAULT:
      default: return 128;
    }
  }

  /// Level -> gzip XFL header byte (RFC 1952 §2.3.1: 2 = best, 4 = fastest).
  static unsigned char xflFor(Level level)
  {
    return (level == Level::BEST) ? 2 : (level == Level::FAST) ? 4 : 0;
  }
};

} // namespace util
} // namespace iora
