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

} // namespace detail

/// \brief Native, zero-dependency gzip (RFC 1952) encoder.
///
/// Emits a complete gzip stream — a from-scratch RFC 1951 DEFLATE body
/// (fixed-Huffman blocks + hash-chain LZ77 over a <=32KB window) wrapped in the
/// RFC 1952 container with a deterministic header (MTIME=0, OS=0xFF) and a
/// CRC-32 + ISIZE trailer. Output is byte-reproducible for a given input+level
/// and decodes under any standard inflater (gunzip, zlib). The raw DEFLATE core
/// is private (namespace detail); only the gzip container is exposed.
///
/// Two entry points:
///   - compress(view, level): one-shot, materializes the whole input.
///   - Encoder: streaming/incremental, so a large file need not be held in RAM.
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
