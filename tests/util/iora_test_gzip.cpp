// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

#include <iora/system/shell_runner.hpp>
#include <iora/util/gzip.hpp>

using iora::util::Gzip;
using Level = iora::util::Gzip::Level;

// ---------------------------------------------------------------------------
// Reference-inflater interop harness (R1 hard gate).
//
// The from-scratch encoder MUST be validated against an INDEPENDENT inflater,
// never our own (future) decoder — a fixture that shares the codec's bug proves
// nothing. We shell out to python3's gzip or the system gunzip via ShellRunner
// (not hand-rolled popen), routing the binary payload through temp files
// because ShellRunner::execute() captures stdout as a C-string (truncates at an
// embedded NUL); file I/O in binary mode is NUL-safe.
//
// H1 (CRITICAL): if NO reference inflater is present, the harness FAILS the
// test — it never skips or silently passes. A missing tool must not vacuate the
// gate that is the encoder's entire correctness backstop.
// ---------------------------------------------------------------------------
namespace
{

std::string uniqueTempPath(const char *tag)
{
  static std::atomic<std::uint64_t> counter{0};
  std::ostringstream os;
  os << "/tmp/iora_gzip_test_" << tag << "_" << ::getpid() << "_"
     << counter.fetch_add(1);
  return os.str();
}

/// RAII: unlink a temp file on scope exit, even when a Catch2 REQUIRE throws.
struct TempFileGuard
{
  std::string path;
  ~TempFileGuard()
  {
    if (!path.empty())
    {
      ::unlink(path.c_str());
    }
  }
};

bool commandAvailable(const std::string &tool)
{
  iora::system::ExecutionOptions opts;
  opts.throwOnError = false;
  auto r = iora::system::ShellRunner::executeWithOptions(
    "command -v " + tool + " >/dev/null 2>&1", opts);
  return r.exitCode == 0;
}

bool havePython3() { return commandAvailable("python3"); }
bool haveGunzip() { return commandAvailable("gunzip"); }

/// At least one independent inflater must exist, or the gate is vacuous.
bool referenceInflaterAvailable() { return havePython3() || haveGunzip(); }

void writeFileBinary(const std::string &path, std::string_view data)
{
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  REQUIRE(f.is_open());
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
  f.flush();
  REQUIRE(f.good());
}

std::string readFileBinary(const std::string &path)
{
  std::ifstream f(path, std::ios::binary);
  REQUIRE(f.is_open());
  std::ostringstream os;
  os << f.rdbuf();
  return os.str();
}

/// Decode \p gzStream with an independent inflater and return the plaintext.
/// \p which selects "python3" or "gunzip"; both must round-trip identically
/// where present. FAILS the test if the requested tool is unavailable.
std::string referenceInflateWith(const std::string &which,
                                 std::string_view gzStream)
{
  const std::string in = uniqueTempPath("in");
  const std::string out = uniqueTempPath("out");
  TempFileGuard inGuard{in};   // unlinked even if a REQUIRE below throws
  TempFileGuard outGuard{out};
  writeFileBinary(in, gzStream);

  std::string cmd;
  if (which == "python3")
  {
    cmd = "python3 -c \"import sys,gzip; "
          "open('" + out + "','wb').write("
          "gzip.decompress(open('" + in + "','rb').read()))\"";
  }
  else
  {
    cmd = "gunzip -c '" + in + "' > '" + out + "'";
  }

  iora::system::ExecutionOptions opts;
  opts.throwOnError = false;
  opts.captureStderr = true;
  auto r = iora::system::ShellRunner::executeWithOptions(cmd, opts);
  INFO(which << " exitCode=" << r.exitCode << " stderr=" << r.stderr);
  REQUIRE(r.exitCode == 0);

  std::string plaintext = readFileBinary(out);
  return plaintext; // temp files unlinked by the RAII guards above
}

/// Round-trip through EVERY available reference inflater and assert they all
/// agree; returns the recovered plaintext. Hard-fails if none is available.
[[maybe_unused]] std::string referenceInflate(std::string_view gzStream)
{
  // Availability is fixed for the process; probe each tool at most once rather
  // than spawning `command -v` per corpus entry.
  static const bool py = havePython3();
  static const bool gz = haveGunzip();
  if (!py && !gz)
  {
    FAIL("no reference inflater (python3 or gunzip) available — the interop "
         "gate cannot be satisfied; install one rather than skipping (H1)");
  }

  std::string result;
  bool haveResult = false;
  if (py)
  {
    result = referenceInflateWith("python3", gzStream);
    haveResult = true;
  }
  if (gz)
  {
    std::string viaGunzip = referenceInflateWith("gunzip", gzStream);
    if (haveResult)
    {
      REQUIRE(viaGunzip == result); // cross-decode: both must agree
    }
    else
    {
      result = viaGunzip;
      haveResult = true;
    }
  }
  REQUIRE(haveResult);
  return result;
}

// --- Corpus builders --------------------------------------------------------

std::string repeat(const std::string &unit, std::size_t times)
{
  std::string s;
  s.reserve(unit.size() * times);
  for (std::size_t i = 0; i < times; ++i)
  {
    s += unit;
  }
  return s;
}

std::string incompressibleRandom(std::size_t n, std::uint32_t seed)
{
  // Deterministic PRNG (fixed seed) so the "random" corpus is reproducible.
  std::mt19937 rng(seed);
  std::string s;
  s.reserve(n);
  for (std::size_t i = 0; i < n; ++i)
  {
    s.push_back(static_cast<char>(rng() & 0xFFu));
  }
  return s;
}

std::string karooLogSample()
{
  // Representative repetitive SIP/telecom log text (highly compressible).
  std::string line =
    "2026-09-03 14:22:07.123 [INFO ] karoo_tmc.ClientRouter route INVITE "
    "sip:+15551234567@edge.example.com;ctid=abcd tenant=acme trunk=teams "
    "call-id=0123456789abcdef branch=z9hG4bK-524287-1---deadbeef\n";
  return repeat(line, 200);
}

// Named corpus entries for the interop gate.
std::vector<std::pair<std::string, std::string>> buildCorpus()
{
  std::vector<std::pair<std::string, std::string>> c;
  c.emplace_back("empty", std::string());
  c.emplace_back("one-byte", std::string("Q"));
  c.emplace_back("two-bytes", std::string("\0\xFF", 2));
  c.emplace_back("text", std::string("The quick brown fox jumps over the lazy "
                                     "dog. The quick brown fox again."));
  c.emplace_back("embedded-nul", std::string("aaa\0bbb\0ccc", 11));
  c.emplace_back("incompressible-random", incompressibleRandom(20000, 0xC0FFEEu));
  c.emplace_back("highly-repetitive", repeat("AB", 20000));
  c.emplace_back("window-boundary-32768", repeat("x", 32768));
  c.emplace_back("just-over-window", incompressibleRandom(40000, 0x1234u));
  c.emplace_back("multi-segment", repeat("karoo-", 20000)); // > 2 stream segments
  c.emplace_back("karoo-log", karooLogSample());
  return c;
}

} // namespace

TEST_CASE("gzip interop harness has a reference inflater (H1 FAIL-not-SKIP)",
          "[gzip][interop]")
{
  // On a host with neither python3 nor gunzip this REQUIRE fails the suite
  // rather than skipping — the interop gate must never be silently vacuated.
  REQUIRE(referenceInflaterAvailable());
}

TEST_CASE("gzip one-shot compress round-trips through a reference inflater",
          "[gzip][interop]")
{
  // R1 HARD gate: every corpus entry must inflate back to itself under an
  // INDEPENDENT inflater (python3 gzip / gunzip), cross-decoded where both are
  // present. Never validated by our own decoder.
  for (const auto &entry : buildCorpus())
  {
    const std::string &name = entry.first;
    const std::string &plain = entry.second;
    INFO("corpus=" << name << " size=" << plain.size());
    for (Level level : {Level::FAST, Level::DEFAULT, Level::BEST})
    {
      const std::string gz = Gzip::compress(plain, level);
      REQUIRE(referenceInflate(gz) == plain);
    }
  }
}

TEST_CASE("gzip actually compresses repetitive input (LZ77 back-references)",
          "[gzip]")
{
  const std::string repetitive = repeat("AB", 20000); // 40000 bytes
  const std::string gz = Gzip::compress(repetitive, Level::DEFAULT);
  // If LZ77 matching works, the gzip stream is far smaller than the input.
  REQUIRE(gz.size() < repetitive.size() / 4);
  REQUIRE(referenceInflate(gz) == repetitive);
}

TEST_CASE("gzip output is deterministic (byte-identical across runs)",
          "[gzip][determinism]")
{
  for (const auto &entry : buildCorpus())
  {
    INFO("corpus=" << entry.first);
    for (Level level : {Level::FAST, Level::DEFAULT, Level::BEST})
    {
      REQUIRE(Gzip::compress(entry.second, level) ==
              Gzip::compress(entry.second, level));
    }
  }
  // Golden-ish stability: a fixed small input yields a fixed size+content twice.
  const std::string fixed = "iora-gzip-determinism-probe-0123456789";
  REQUIRE(Gzip::compress(fixed, Level::DEFAULT) ==
          Gzip::compress(fixed, Level::DEFAULT));
}

TEST_CASE("gzip header/trailer framing is well-formed (RFC 1952)", "[gzip]")
{
  const std::string gz = Gzip::compress("hello world", Level::DEFAULT);
  REQUIRE(gz.size() >= 18); // 10-byte header + >=0 body + 8-byte trailer
  REQUIRE(static_cast<unsigned char>(gz[0]) == 0x1f);
  REQUIRE(static_cast<unsigned char>(gz[1]) == 0x8b);
  REQUIRE(static_cast<unsigned char>(gz[2]) == 0x08); // CM = deflate
  REQUIRE(static_cast<unsigned char>(gz[3]) == 0x00); // FLG = 0
  REQUIRE(static_cast<unsigned char>(gz[4]) == 0x00); // MTIME = 0 (determinism)
  REQUIRE(static_cast<unsigned char>(gz[5]) == 0x00);
  REQUIRE(static_cast<unsigned char>(gz[6]) == 0x00);
  REQUIRE(static_cast<unsigned char>(gz[7]) == 0x00);
  REQUIRE(static_cast<unsigned char>(gz[9]) == 0xFF); // OS = unknown
  // Trailer ISIZE (last 4 bytes, little-endian) == uncompressed length.
  const std::size_t n = gz.size();
  const std::uint32_t isize =
    static_cast<std::uint32_t>(static_cast<unsigned char>(gz[n - 4])) |
    (static_cast<std::uint32_t>(static_cast<unsigned char>(gz[n - 3])) << 8) |
    (static_cast<std::uint32_t>(static_cast<unsigned char>(gz[n - 2])) << 16) |
    (static_cast<std::uint32_t>(static_cast<unsigned char>(gz[n - 1])) << 24);
  REQUIRE(isize == 11u);
}

TEST_CASE("gzip streaming encoder is decode-equivalent to one-shot",
          "[gzip][streaming]")
{
  // Memory-bound note (task-4.1 "peak RSS does not scale with file size"):
  // peak RSS is impractical to assert portably and _buf is private, but the
  // memory-bounding path (Encoder::trimHistory) is behaviorally exercised here
  // and in the chunk-independence test — the multi-segment corpus entries
  // (>=120KB, several 32KB segments) only decode correctly if trimHistory
  // re-bases the retained window right, so a broken bound would fail these
  // reference round-trips. The retained buffer is structurally <= 32KB window +
  // one pending segment regardless of total input size.
  for (const auto &entry : buildCorpus())
  {
    INFO("corpus=" << entry.first << " size=" << entry.second.size());
    const std::string &plain = entry.second;

    // Feed the input in small, unaligned chunks through the streaming encoder.
    Gzip::Encoder enc(Level::DEFAULT);
    std::string streamed;
    const std::size_t step = 1000;
    for (std::size_t i = 0; i < plain.size(); i += step)
    {
      streamed += enc.update(
        std::string_view(plain.data() + i, std::min(step, plain.size() - i)));
    }
    streamed += enc.finish();

    // Decode-equivalent to one-shot (same plaintext), not byte-identical.
    REQUIRE(referenceInflate(streamed) == plain);
    REQUIRE(referenceInflate(streamed) == referenceInflate(Gzip::compress(plain)));
  }
}

TEST_CASE("gzip streaming output is byte-identical across runs (determinism)",
          "[gzip][streaming][determinism]")
{
  auto streamOnce = [](const std::string &plain) {
    Gzip::Encoder enc(Level::DEFAULT);
    std::string out;
    const std::size_t step = 777; // odd chunking, still content-deterministic
    for (std::size_t i = 0; i < plain.size(); i += step)
    {
      out += enc.update(
        std::string_view(plain.data() + i, std::min(step, plain.size() - i)));
    }
    out += enc.finish();
    return out;
  };
  const std::string plain = repeat("karoo-", 20000);
  REQUIRE(streamOnce(plain) == streamOnce(plain));
}

TEST_CASE("gzip Encoder is move-only (L2)", "[gzip][streaming]")
{
  STATIC_REQUIRE_FALSE(std::is_copy_constructible<Gzip::Encoder>::value);
  STATIC_REQUIRE_FALSE(std::is_copy_assignable<Gzip::Encoder>::value);
  STATIC_REQUIRE(std::is_move_constructible<Gzip::Encoder>::value);
}

TEST_CASE("gzip streaming output is chunk-independent (content-only)",
          "[gzip][streaming][determinism]")
{
  // The comment on the streaming path claims output depends only on content,
  // not on how the caller chunks update(). Feed the SAME input with two very
  // different chunk sizes and require byte-identical streamed output.
  auto streamWithChunk = [](const std::string &plain, std::size_t step) {
    Gzip::Encoder enc(Level::DEFAULT);
    std::string out;
    for (std::size_t i = 0; i < plain.size(); i += step)
    {
      out += enc.update(
        std::string_view(plain.data() + i, std::min(step, plain.size() - i)));
    }
    out += enc.finish();
    return out;
  };
  const std::string plain = repeat("karoo-log-", 15000); // spans many segments
  REQUIRE(streamWithChunk(plain, 333) == streamWithChunk(plain, 4096));
  REQUIRE(streamWithChunk(plain, 1) == streamWithChunk(plain, 200000));
}

// --- Discrete unit tests for the detail:: DEFLATE primitives (task-2.1/2.3) --

TEST_CASE("detail::BitWriter packs bits LSB-first (task-2.1)", "[gzip][unit]")
{
  using iora::util::detail::BitWriter;
  {
    BitWriter w;
    w.putBits(0xABu, 8);
    REQUIRE(w.buffer().size() == 1);
    REQUIRE(static_cast<unsigned char>(w.buffer()[0]) == 0xAB);
  }
  {
    // 3+2+3 bits: [1,0,1][1,1][1,1,1] -> byte value sum(bit_i<<i)
    // = 1 + 0 + 4 + 8 + 16 + 32 + 64 + 128 = 0xFD.
    BitWriter w;
    w.putBits(0b101u, 3);
    w.putBits(0b11u, 2);
    w.putBits(0b111u, 3);
    REQUIRE(w.buffer().size() == 1);
    REQUIRE(static_cast<unsigned char>(w.buffer()[0]) == 0xFD);
  }
  {
    // Partial bits stay in the accumulator until aligned.
    BitWriter w;
    w.putBits(0b1u, 1);
    REQUIRE(w.buffer().empty()); // 1 bit: no complete byte yet
    w.alignToByte();
    REQUIRE(w.buffer().size() == 1);
    REQUIRE(static_cast<unsigned char>(w.buffer()[0]) == 0x01);
  }
}

TEST_CASE("detail::reverseBits reverses the low bits", "[gzip][unit]")
{
  using iora::util::detail::reverseBits;
  REQUIRE(reverseBits(0x30u, 8) == 0x0Cu);  // 00110000 -> 00001100
  REQUIRE(reverseBits(0b1u, 3) == 0b100u);  // 001 -> 100
  REQUIRE(reverseBits(0x190u, 9) == 0x13u); // 110010000 -> 000010011
}

TEST_CASE("detail fixed-Huffman canonical codes match RFC 1951 §3.2.6",
          "[gzip][unit]")
{
  namespace d = iora::util::detail;
  auto codes = d::canonicalCodes(d::fixedLitLengths());
  // The canonical (MSB-first) fixed literal/length codes from the RFC.
  REQUIRE(codes[0] == 0x30u);   // symbol 0   -> 8-bit 00110000
  REQUIRE(codes[143] == 0xBFu); // symbol 143 -> 8-bit 10111111
  REQUIRE(codes[144] == 0x190u); // symbol 144 -> 9-bit 110010000
  REQUIRE(codes[255] == 0x1FFu); // symbol 255 -> 9-bit 111111111
  REQUIRE(codes[256] == 0x00u);  // symbol 256 (EOB) -> 7-bit 0000000
  REQUIRE(codes[279] == 0x17u);  // symbol 279 -> 7-bit 0010111
  REQUIRE(codes[280] == 0xC0u);  // symbol 280 -> 8-bit 11000000
  REQUIRE(codes[287] == 0xC7u);  // symbol 287 -> 8-bit 11000111

  // Code LENGTHS in the pre-reversed emission table.
  const d::FixedHuff &h = d::fixedHuff();
  REQUIRE(h.litLen[0] == 8);
  REQUIRE(h.litLen[144] == 9);
  REQUIRE(h.litLen[256] == 7);
  REQUIRE(h.litLen[280] == 8);
  REQUIRE(h.distLen[0] == 5);
  // The emission table stores the bit-reversed code (reverse of 0x30 over 8b).
  REQUIRE(h.litCode[0] == d::reverseBits(0x30u, 8));
}

// Frozen golden bytes of Gzip::compress("iora-gzip-determinism-probe-...",
// DEFAULT). Regenerate deliberately (see scratch golden.cpp) only on an
// intentional format change.
#define GZIP_GOLDEN_DEFAULT                                                     \
  std::vector<unsigned char>                                                   \
  {                                                                            \
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xcb, 0xcc,    \
      0x2f, 0x4a, 0xd4, 0x4d, 0xaf, 0xca, 0x2c, 0xd0, 0x4d, 0x49, 0x2d, 0x49,  \
      0x2d, 0xca, 0xcd, 0xcc, 0xcb, 0x2c, 0xce, 0xd5, 0x2d, 0x28, 0xca, 0x4f,  \
      0x4a, 0xd5, 0x35, 0x30, 0x34, 0x32, 0x36, 0x31, 0x35, 0x33, 0xb7, 0xb0,  \
      0x04, 0x00, 0xc3, 0x60, 0xe7, 0x6b, 0x26, 0x00, 0x00, 0x00              \
  }

TEST_CASE("gzip DEFAULT output matches a committed golden vector (task-5.2)",
          "[gzip][determinism]")
{
  // A frozen reference encoding of a fixed input at DEFAULT (greedy, per
  // L-new-3). Unlike compress(x)==compress(x) self-comparison, this catches ANY
  // change to the deflate body/format across builds (reproducible-build guard).
  // Regenerate deliberately only when an intentional format change is made.
  const std::string fixed = "iora-gzip-determinism-probe-0123456789";
  const std::vector<unsigned char> golden = GZIP_GOLDEN_DEFAULT;
  const std::string gz = Gzip::compress(fixed, Level::DEFAULT);
  std::vector<unsigned char> got(gz.begin(), gz.end());
  REQUIRE(got == golden);
  // And it must still decode back to the input.
  REQUIRE(referenceInflate(gz) == fixed);
}
