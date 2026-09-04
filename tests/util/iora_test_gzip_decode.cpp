// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include <iora/system/shell_runner.hpp>
#include <iora/util/gzip.hpp>

// ---------------------------------------------------------------------------
// Decoder (Gzip::decompress) tests. The encoder's correctness gate proves our
// bytes are well-formed; the DECODER's gate is the mirror image plus untrusted-
// input hardening:
//   - a REFERENCE ENCODER (python3 gzip / system gzip) produces the corpus —
//     including DYNAMIC-Huffman streams our own encoder never emits — and our
//     decoder must reproduce the original (cross-decode, not self-round-trip).
//   - a malformed corpus + a deterministic fuzz loop assert: never crash, never
//     read OOB (ASan), never exceed the output cap, always terminate.
// Binary payloads are routed through temp files because ShellRunner::execute()
// captures stdout as a C-string (truncates at an embedded NUL).
// ---------------------------------------------------------------------------

namespace
{
using iora::util::Crc32;
using iora::util::Gzip;
namespace detail = iora::util::detail;
using Err = Gzip::DecompressError;

std::string uniqueTempPath(const char *tag)
{
  static std::atomic<std::uint64_t> counter{0};
  std::ostringstream os;
  os << "/tmp/iora_gzip_decode_test_" << tag << "_" << ::getpid() << "_"
     << counter.fetch_add(1);
  return os.str();
}

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
bool haveGzipCli() { return commandAvailable("gzip"); }

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

/// gzip-compress \p data with python3 (dynamic-Huffman via zlib). When
/// \p filename is non-empty the stream carries an FNAME header field, so the
/// decoder's header optional-field parsing is exercised against real output.
std::string refGzipPython(std::string_view data, const std::string &filename = "")
{
  const std::string in = uniqueTempPath("pin");
  const std::string out = uniqueTempPath("pout");
  TempFileGuard inG{in};
  TempFileGuard outG{out};
  writeFileBinary(in, data);

  std::string cmd;
  if (filename.empty())
  {
    cmd = "python3 -c \"import gzip; "
          "open('" + out + "','wb').write("
          "gzip.compress(open('" + in + "','rb').read()))\"";
  }
  else
  {
    cmd = "python3 -c \"import gzip,io; "
          "d=open('" + in + "','rb').read(); buf=io.BytesIO(); "
          "f=gzip.GzipFile(fileobj=buf,mode='wb',filename='" + filename +
          "',mtime=0); f.write(d); f.close(); "
          "open('" + out + "','wb').write(buf.getvalue())\"";
  }

  iora::system::ExecutionOptions opts;
  opts.throwOnError = false;
  opts.captureStderr = true;
  auto r = iora::system::ShellRunner::executeWithOptions(cmd, opts);
  INFO("python3 gzip exitCode=" << r.exitCode << " stderr=" << r.stderr);
  REQUIRE(r.exitCode == 0);
  return readFileBinary(out);
}

/// gzip-compress \p data with the system `gzip` CLI (an independent encoder).
std::string refGzipCli(std::string_view data)
{
  const std::string in = uniqueTempPath("cin");
  const std::string out = uniqueTempPath("cout");
  TempFileGuard inG{in};
  TempFileGuard outG{out};
  writeFileBinary(in, data);
  const std::string cmd = "gzip -c '" + in + "' > '" + out + "'";
  iora::system::ExecutionOptions opts;
  opts.throwOnError = false;
  opts.captureStderr = true;
  auto r = iora::system::ShellRunner::executeWithOptions(cmd, opts);
  INFO("gzip -c exitCode=" << r.exitCode << " stderr=" << r.stderr);
  REQUIRE(r.exitCode == 0);
  return readFileBinary(out);
}

/// Assemble a gzip stream: a clean FLG=0 header, the given raw DEFLATE \p body,
/// and a trailer whose CRC-32/ISIZE are computed over \p trailerPayload (pass
/// the intended plaintext for a valid stream, or anything for a body that is
/// meant to fail before the trailer is reached).
std::string makeGzip(const std::string &body, std::string_view trailerPayload)
{
  std::string s = detail::gzipHeader(0);
  s += body;
  detail::appendLE32(s, Crc32::compute(trailerPayload));
  detail::appendLE32(
    s, static_cast<std::uint32_t>(trailerPayload.size() & 0xFFFFFFFFu));
  return s;
}

/// Assert a stream is rejected as MALFORMED_INPUT (names the recurring intent
/// without weakening any assertion — the two checks are identical to inline).
void requireMalformed(std::string_view gz, std::size_t cap = (1u << 20))
{
  auto r = Gzip::decompress(gz, cap);
  REQUIRE(r.isErr());
  REQUIRE(r.error() == Err::MALFORMED_INPUT);
}

/// Build a raw DEFLATE dynamic (BTYPE=10) block header carrying EXACTLY the
/// given literal and distance code-length arrays, with no RLE: the code-length
/// alphabet assigns symbols 0..15 a complete 4-bit code, and each length value
/// is emitted directly. Lets a test craft a specific over-subscribed /
/// incomplete literal or distance table; decode fails at table validation
/// before any block body, so no body is appended. \p litLens must be >= 257
/// entries and \p distLens >= 1.
std::string dynHeader(const std::vector<int> &litLens,
                      const std::vector<int> &distLens)
{
  static constexpr int order[19] = {16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                    11, 4,  12, 3, 13, 2, 14, 1, 15};
  detail::BitWriter bw;
  bw.putBits(1u, 1); // BFINAL
  bw.putBits(2u, 2); // BTYPE=10 dynamic
  bw.putBits(static_cast<std::uint32_t>(litLens.size() - 257), 5);  // HLIT
  bw.putBits(static_cast<std::uint32_t>(distLens.size() - 1), 5);   // HDIST
  bw.putBits(static_cast<std::uint32_t>(19 - 4), 4);               // HCLEN=19
  for (int i = 0; i < 19; ++i)
  {
    // symbols 0..15 -> length 4 (a complete code); 16/17/18 unused -> 0.
    bw.putBits((order[i] <= 15) ? 4u : 0u, 3);
  }
  // Each code length is CL symbol v (0..15), whose canonical 4-bit code equals v
  // (MSB-first) — reversed for the LSB-first writer.
  auto emitLen = [&](int v) {
    bw.putBits(detail::reverseBits(static_cast<std::uint32_t>(v), 4), 4);
  };
  for (int v : litLens)
  {
    emitLen(v);
  }
  for (int v : distLens)
  {
    emitLen(v);
  }
  bw.alignToByte();
  return bw.buffer();
}

/// A complete literal/length code-length array (symbol 0 and EOB 256 each get a
/// 1-bit code): used as the valid literal side when crafting a broken distance
/// table.
std::vector<int> completeLitLengths()
{
  std::vector<int> lens(257, 0);
  lens[0] = 1;
  lens[256] = 1;
  return lens;
}

/// A large, moderately-varied text sample (compresses as dynamic-Huffman and is
/// bigger than the 32KB window).
std::string bigVariedSample()
{
  std::string s;
  std::mt19937 rng(20260904);
  static const char *words[] = {"INVITE ", "sip:alice@", "example.com ",
                                "SIP/2.0\r\n", "Via: ", "branch=z9hG4bK",
                                "Contact: ", "Expires=3600 ", "REGISTER ",
                                "200 OK "};
  while (s.size() < 100000)
  {
    s += words[rng() % 10];
    if ((rng() & 7u) == 0)
    {
      s += std::to_string(rng());
    }
  }
  return s;
}

} // namespace

// ── task-4.1: reference-encoder cross-decode round-trip (incl. dynamic) ──────

TEST_CASE("gzip decode interop harness has a reference encoder (FAIL-not-SKIP)",
          "[gzip][decode][interop]")
{
  // Mirrors the encoder gate's H1 rule: a missing reference encoder must fail
  // the suite, not vacuously pass it.
  REQUIRE((havePython3() || haveGzipCli()));
}

TEST_CASE("gzip decode round-trips a reference-encoded corpus (dynamic-Huffman)",
          "[gzip][decode][interop]")
{
  if (!havePython3())
  {
    WARN("python3 unavailable; dynamic-Huffman corpus skipped this run");
    return;
  }
  const std::string log =
    "2026-09-04 12:00:00.123 [INFO] call=abc123 REGISTER sip:alice@ex.com\n";
  std::vector<std::string> corpus = {
    "",
    "A",
    std::string(64, 'Z'),                 // highly repetitive
    log,
    bigVariedSample(),                    // > 32KB, dynamic-Huffman
  };
  // an incompressible random block
  {
    std::string rnd(4096, '\0');
    std::mt19937 g(777);
    for (char &c : rnd)
    {
      c = static_cast<char>(g() & 0xFF);
    }
    corpus.push_back(rnd);
  }

  for (const auto &plain : corpus)
  {
    const std::string gz = refGzipPython(plain);
    auto r = Gzip::decompress(gz, 1u << 20);
    INFO("python corpus entry size=" << plain.size());
    REQUIRE(r.isOk());
    REQUIRE(r.value() == plain);
  }
}

TEST_CASE("gzip decode reads a stream carrying an FNAME header field",
          "[gzip][decode][interop][header]")
{
  if (!havePython3())
  {
    WARN("python3 unavailable; FNAME header test skipped this run");
    return;
  }
  const std::string plain = "payload behind an FNAME-bearing gzip header";
  const std::string gz = refGzipPython(plain, "original.log");
  // sanity: FLG FNAME bit (0x08) is actually set in the produced stream
  REQUIRE(gz.size() > 4);
  REQUIRE((static_cast<unsigned char>(gz[3]) & 0x08u) != 0u);
  auto r = Gzip::decompress(gz, 1u << 20);
  REQUIRE(r.isOk());
  REQUIRE(r.value() == plain);
}

TEST_CASE("gzip decode round-trips system-gzip (`gzip -c`) output",
          "[gzip][decode][interop]")
{
  if (!haveGzipCli())
  {
    WARN("system gzip unavailable; CLI corpus skipped this run");
    return;
  }
  for (const std::string &plain :
       {std::string("hello world"), std::string(50000, 'q'), std::string("")})
  {
    const std::string gz = refGzipCli(plain);
    auto r = Gzip::decompress(gz, 1u << 20);
    REQUIRE(r.isOk());
    REQUIRE(r.value() == plain);
  }
}

// ── task-4.2: our-encoder -> our-decoder self-round-trip + empty ─────────────

TEST_CASE("gzip decode round-trips our own encoder (fixed-Huffman)",
          "[gzip][decode]")
{
  for (const std::string &plain :
       {std::string(""), std::string("hello"),
        std::string("the quick brown fox jumps over the lazy dog"),
        std::string(70000, 'x')})
  {
    const std::string gz = Gzip::compress(plain);
    auto r = Gzip::decompress(gz, 1u << 20);
    INFO("self round-trip size=" << plain.size());
    REQUIRE(r.isOk());
    REQUIRE(r.value() == plain);
  }
}

TEST_CASE("gzip decode of the empty payload yields a present empty string",
          "[gzip][decode]")
{
  const std::string gz = Gzip::compress("");
  auto r = Gzip::decompress(gz, 1u << 20);
  REQUIRE(r.isOk());
  REQUIRE(r.value().empty());
}

TEST_CASE("gzip decode round-trips the streaming Encoder output", "[gzip][decode]")
{
  Gzip::Encoder enc;
  std::string gz;
  const std::string part1(40000, 'a');
  const std::string part2 = "tail chunk with different bytes 0123456789";
  gz += enc.update(part1);
  gz += enc.update(part2);
  gz += enc.finish();
  auto r = Gzip::decompress(gz, 1u << 20);
  REQUIRE(r.isOk());
  REQUIRE(r.value() == part1 + part2);
}

TEST_CASE("gzip decode of a hand-built STORED block (BTYPE=00)", "[gzip][decode]")
{
  detail::BitWriter bw;
  bw.putBits(1u, 1); // BFINAL
  bw.putBits(0u, 2); // BTYPE=00 stored
  bw.alignToByte();
  std::string body = bw.buffer();
  const std::string payload = "hello";
  body.push_back(static_cast<char>(payload.size() & 0xFF)); // LEN low
  body.push_back(0);                                        // LEN high
  body.push_back(static_cast<char>(~payload.size() & 0xFF)); // NLEN low
  body.push_back(static_cast<char>(0xFF));                  // NLEN high
  body += payload;
  const std::string gz = makeGzip(body, payload);
  auto r = Gzip::decompress(gz, 100);
  REQUIRE(r.isOk());
  REQUIRE(r.value() == payload);
}

TEST_CASE("gzip decode ignores reserved FLG bits (zlib-compatible)",
          "[gzip][decode][header]")
{
  std::string gz = Gzip::compress("reserved bits must be ignored");
  gz[3] = static_cast<char>(static_cast<unsigned char>(gz[3]) | 0x20u); // reserved bit 5
  auto r = Gzip::decompress(gz, 1u << 20);
  REQUIRE(r.isOk());
  REQUIRE(r.value() == "reserved bits must be ignored");
}

// ── task-4.3: malformed corpus -> clean error, no crash ──────────────────────

// Build a 10-byte gzip base header with the given FLG byte (magic, CM=8).
namespace
{
std::string headerWithFlg(unsigned char flg)
{
  std::string s;
  s.push_back(static_cast<char>(0x1f));
  s.push_back(static_cast<char>(0x8b));
  s.push_back(static_cast<char>(0x08));
  s.push_back(static_cast<char>(flg));
  for (int i = 0; i < 6; ++i)
  {
    s.push_back(0); // MTIME(4) / XFL / OS
  }
  return s;
}
} // namespace

TEST_CASE("gzip decode rejects malformed streams cleanly (no crash)",
          "[gzip][decode][malformed]")
{
  const std::string valid = Gzip::compress("the quick brown fox");

  SECTION("truncated stream")
  {
    for (std::size_t drop : {std::size_t(1), std::size_t(5), std::size_t(9)})
    {
      if (drop < valid.size())
      {
        requireMalformed(valid.substr(0, valid.size() - drop));
      }
    }
  }
  SECTION("bad magic")
  {
    std::string s = valid;
    s[0] = 0x00;
    requireMalformed(s);
  }
  SECTION("bad compression method (CM != 8)")
  {
    std::string s = valid;
    s[2] = 0x07;
    requireMalformed(s);
  }
  SECTION("corrupt CRC")
  {
    std::string s = valid;
    s[s.size() - 8] ^= 0xFF;
    requireMalformed(s);
  }
  SECTION("corrupt ISIZE")
  {
    std::string s = valid;
    s[s.size() - 1] ^= 0xFF;
    requireMalformed(s);
  }
  SECTION("trailing bytes after a valid member")
  {
    std::string s = valid;
    s.push_back('!');
    requireMalformed(s);
  }
  SECTION("reserved BTYPE=11")
  {
    detail::BitWriter bw;
    bw.putBits(1u, 1); // BFINAL
    bw.putBits(3u, 2); // BTYPE=11 reserved
    bw.alignToByte();
    requireMalformed(makeGzip(bw.buffer(), ""));
  }
  SECTION("stored block NLEN != ~LEN")
  {
    detail::BitWriter bw;
    bw.putBits(1u, 1);
    bw.putBits(0u, 2); // BTYPE=00
    bw.alignToByte();
    std::string body = bw.buffer();
    body.push_back(3);
    body.push_back(0); // LEN=3
    body.push_back(0);
    body.push_back(0); // NLEN=0 (should be ~3)
    body += "abc";
    requireMalformed(makeGzip(body, "abc"));
  }
  SECTION("stored block LEN past end of input")
  {
    detail::BitWriter bw;
    bw.putBits(1u, 1);
    bw.putBits(0u, 2); // BTYPE=00
    bw.alignToByte();
    std::string body = bw.buffer();
    body.push_back(100);
    body.push_back(0); // LEN=100
    body.push_back(static_cast<char>(~100 & 0xFF));
    body.push_back(static_cast<char>(0xFF)); // NLEN = ~100
    body += "ab";                            // only 2 data bytes, far fewer than 100
    requireMalformed(makeGzip(body, ""));
  }
  SECTION("back-reference distance past output start")
  {
    detail::BitWriter bw;
    bw.putBits(1u, 1);
    bw.putBits(1u, 2); // BTYPE=01 fixed
    detail::emitMatch(bw, detail::fixedHuff(), 3, 1); // match before any literal
    detail::emitSymbol(bw, detail::fixedHuff(), 256);
    bw.alignToByte();
    requireMalformed(makeGzip(bw.buffer(), ""));
  }
  SECTION("invalid length symbol (286)")
  {
    detail::BitWriter bw;
    bw.putBits(1u, 1);
    bw.putBits(1u, 2); // BTYPE=01 fixed
    detail::emitSymbol(bw, detail::fixedHuff(), 286); // 286 is not a valid length code
    bw.alignToByte();
    requireMalformed(makeGzip(bw.buffer(), ""));
  }
  SECTION("invalid (unassigned) distance code in a fixed block")
  {
    // Fixed distance codes are 5-bit; symbols 0..29 are assigned, 30/31 are not.
    // Emit a valid length symbol (257 -> length 3) then the unassigned 5-bit
    // distance pattern 11110, which decodes to no symbol.
    detail::BitWriter bw;
    bw.putBits(1u, 1);
    bw.putBits(1u, 2);                                 // BTYPE=01 fixed
    detail::emitSymbol(bw, detail::fixedHuff(), 257);  // length symbol (len 3)
    bw.putBits(15u, 5); // stream bits 1,1,1,1,0 -> code 11110 (unassigned)
    bw.alignToByte();
    requireMalformed(makeGzip(bw.buffer(), ""));
  }
  SECTION("dynamic block with over-subscribed code-length table")
  {
    detail::BitWriter bw;
    bw.putBits(1u, 1); // BFINAL
    bw.putBits(2u, 2); // BTYPE=10 dynamic
    bw.putBits(0u, 5); // HLIT  -> 257
    bw.putBits(0u, 5); // HDIST -> 1
    bw.putBits(0u, 4); // HCLEN -> 4 code-length codes
    bw.putBits(1u, 3); // 4 codes all length 1 -> count[1]=4 -> over-subscribed
    bw.putBits(1u, 3);
    bw.putBits(1u, 3);
    bw.putBits(1u, 3);
    bw.alignToByte();
    requireMalformed(makeGzip(bw.buffer(), ""));
  }
  SECTION("dynamic block with incomplete code-length table")
  {
    detail::BitWriter bw;
    bw.putBits(1u, 1); // BFINAL
    bw.putBits(2u, 2); // BTYPE=10 dynamic
    bw.putBits(0u, 5); // HLIT  -> 257
    bw.putBits(0u, 5); // HDIST -> 1
    bw.putBits(0u, 4); // HCLEN -> 4 code-length codes
    bw.putBits(1u, 3); // one length-1 code, rest 0 -> count[1]=1 -> incomplete
    bw.putBits(0u, 3);
    bw.putBits(0u, 3);
    bw.putBits(0u, 3);
    bw.alignToByte();
    requireMalformed(makeGzip(bw.buffer(), ""));
  }
  SECTION("dynamic block RLE repeat-16 with no previous length")
  {
    // Code-length code: symbols 0 and 16 each length 1 (complete). Canonical
    // codes place symbol 0 -> code 0, symbol 16 -> code 1. Emitting code-length
    // symbol 16 first (a repeat) with no prior length is malformed.
    detail::BitWriter bw;
    bw.putBits(1u, 1); // BFINAL
    bw.putBits(2u, 2); // BTYPE=10 dynamic
    bw.putBits(0u, 5); // HLIT  -> 257
    bw.putBits(0u, 5); // HDIST -> 1
    bw.putBits(0u, 4); // HCLEN -> 4 (order 16,17,18,0)
    bw.putBits(1u, 3); // order[0]=16 -> len 1
    bw.putBits(0u, 3); // order[1]=17 -> len 0
    bw.putBits(0u, 3); // order[2]=18 -> len 0
    bw.putBits(1u, 3); // order[3]=0  -> len 1
    bw.putBits(1u, 1); // first code-length symbol: code 1 -> symbol 16 (repeat)
    bw.alignToByte();
    requireMalformed(makeGzip(bw.buffer(), ""));
  }
  SECTION("dynamic block HLIT out of range (> 286)")
  {
    detail::BitWriter bw;
    bw.putBits(1u, 1);
    bw.putBits(2u, 2);  // BTYPE=10
    bw.putBits(30u, 5); // HLIT -> 287 (> 286)
    bw.putBits(0u, 5);
    bw.putBits(0u, 4);
    bw.alignToByte();
    requireMalformed(makeGzip(bw.buffer(), ""));
  }
  SECTION("dynamic block HDIST out of range (> 30)")
  {
    detail::BitWriter bw;
    bw.putBits(1u, 1);
    bw.putBits(2u, 2); // BTYPE=10
    bw.putBits(0u, 5); // HLIT -> 257
    bw.putBits(30u, 5); // HDIST -> 31 (> 30)
    bw.putBits(0u, 4);
    bw.alignToByte();
    requireMalformed(makeGzip(bw.buffer(), ""));
  }
  SECTION("header FEXTRA XLEN claims more bytes than remain")
  {
    std::string s = headerWithFlg(0x04); // FEXTRA
    s.push_back(static_cast<char>(0xFF)); // XLEN low = 255
    s.push_back(static_cast<char>(0xFF)); // XLEN high -> 65535, far beyond input
    requireMalformed(s);
  }
  SECTION("header FNAME with no terminating NUL")
  {
    std::string s = headerWithFlg(0x08); // FNAME
    s += "name-with-no-nul-terminator";  // runs to end of input, no 0x00
    requireMalformed(s);
  }
  SECTION("header FCOMMENT with no terminating NUL")
  {
    std::string s = headerWithFlg(0x10); // FCOMMENT
    s += "comment-with-no-nul";          // runs to end of input, no 0x00
    requireMalformed(s);
  }
}

TEST_CASE("gzip decode rejects malformed dynamic literal/distance tables",
          "[gzip][decode][malformed][dynamic]")
{
  SECTION("over-subscribed literal table")
  {
    std::vector<int> lit(257, 0);
    lit[0] = 1;
    lit[1] = 1;
    lit[2] = 1; // three 1-bit codes -> over-subscribed
    requireMalformed(makeGzip(dynHeader(lit, {0}), ""));
  }
  SECTION("over-subscribed distance table")
  {
    requireMalformed(makeGzip(dynHeader(completeLitLengths(), {1, 1, 1}), ""));
  }
  SECTION("incomplete literal table (non-trivial)")
  {
    std::vector<int> lit(257, 0);
    lit[0] = 2;
    lit[1] = 2; // two 2-bit codes -> incomplete, not the trivial single-code case
    requireMalformed(makeGzip(dynHeader(lit, {0}), ""));
  }
  SECTION("incomplete distance table (non-trivial)")
  {
    requireMalformed(makeGzip(dynHeader(completeLitLengths(), {2, 2}), ""));
  }
}

TEST_CASE("gzip decode validates FHCRC (hand-built header)",
          "[gzip][decode][header]")
{
  // No common reference tool emits FHCRC, so build one: take a valid stream,
  // set the FHCRC flag, and insert the correct header CRC-16 after the base
  // 10-byte header.
  const std::string plain = "fhcrc validated payload";
  const std::string base = Gzip::compress(plain); // FLG=0
  std::string hdr = base.substr(0, 10);
  hdr[3] = static_cast<char>(static_cast<unsigned char>(hdr[3]) | 0x02u); // FHCRC
  const std::uint32_t crc = Crc32::compute(hdr);
  std::string good = hdr;
  good.push_back(static_cast<char>(crc & 0xFF));
  good.push_back(static_cast<char>((crc >> 8) & 0xFF));
  good += base.substr(10); // deflate body + trailer

  SECTION("valid FHCRC decodes")
  {
    auto r = Gzip::decompress(good, 1u << 20);
    REQUIRE(r.isOk());
    REQUIRE(r.value() == plain);
  }
  SECTION("corrupted FHCRC is rejected")
  {
    std::string bad = good;
    bad[10] ^= 0xFF; // flip a header-CRC byte
    requireMalformed(bad);
  }
}

// ── task-4.4: zip-bomb + maxOutputBytes boundary exactness ───────────────────

TEST_CASE("gzip decode rejects a zip-bomb within the output cap",
          "[gzip][decode][security]")
{
  const std::string bomb(1u << 20, 'A'); // 1 MiB of one byte -> tiny gz
  const std::string gz = Gzip::compress(bomb);
  REQUIRE(gz.size() * 50 < bomb.size()); // it really did compress hugely (>50x)

  auto tooSmall = Gzip::decompress(gz, 4096);
  REQUIRE(tooSmall.isErr());
  REQUIRE(tooSmall.error() == Err::OUTPUT_TOO_LARGE);

  auto ok = Gzip::decompress(gz, 1u << 20);
  REQUIRE(ok.isOk());
  REQUIRE(ok.value().size() == bomb.size());
}

TEST_CASE("gzip decode enforces maxOutputBytes boundary exactly",
          "[gzip][decode][security]")
{
  const std::string plain = "hello"; // 5 bytes
  const std::string gz = Gzip::compress(plain);

  SECTION("exactly cap is Ok")
  {
    auto r = Gzip::decompress(gz, 5);
    REQUIRE(r.isOk());
    REQUIRE(r.value() == plain);
  }
  SECTION("one below cap is OUTPUT_TOO_LARGE")
  {
    auto r = Gzip::decompress(gz, 4);
    REQUIRE(r.isErr());
    REQUIRE(r.error() == Err::OUTPUT_TOO_LARGE);
  }
  SECTION("cap 0 admits only the empty payload")
  {
    auto empty = Gzip::decompress(Gzip::compress(""), 0);
    REQUIRE(empty.isOk());
    REQUIRE(empty.value().empty());

    auto nonEmpty = Gzip::decompress(gz, 0);
    REQUIRE(nonEmpty.isErr());
    REQUIRE(nonEmpty.error() == Err::OUTPUT_TOO_LARGE);
  }
}

// ── task-4.5: deterministic fuzz harness (ASan) ──────────────────────────────

TEST_CASE("gzip decode survives fuzzed input (no crash, bounded, terminates)",
          "[gzip][decode][fuzz]")
{
  std::vector<std::string> seeds = {
    Gzip::compress(""),
    Gzip::compress("hello"),
    Gzip::compress(std::string(5000, 'k')),
  };
  if (havePython3())
  {
    seeds.push_back(refGzipPython("dynamic huffman seed for the fuzzer corpus"));
  }

  std::mt19937 rng(0xC0FFEE); // fixed seed: reproducible
  const std::size_t cap = 1u << 20;

  // Termination watchdog (invariant c): a single bounded one-shot decode of a
  // tiny/seed-sized input must complete near-instantly. A generous per-call
  // ceiling turns a hang (were the bound ever broken) into a failed assertion
  // instead of a wedged suite.
  const auto decodeBounded = [&](std::string_view in) {
    const auto t0 = std::chrono::steady_clock::now();
    auto r = Gzip::decompress(in, cap);
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    REQUIRE(elapsed < std::chrono::seconds(5));
    if (r.isOk())
    {
      REQUIRE(r.value().size() <= cap); // (b) output never exceeds the cap
    }
  };

  for (int iter = 0; iter < 20000; ++iter)
  {
    std::string s = seeds[rng() % seeds.size()];
    if (!s.empty())
    {
      const int mutations = 1 + static_cast<int>(rng() % 4u);
      for (int m = 0; m < mutations; ++m)
      {
        s[rng() % s.size()] ^= static_cast<char>(1u << (rng() % 8u));
      }
    }
    // (a) no crash / ASan report, (b) output <= cap, (c) terminates.
    decodeBounded(s);
  }

  // Also feed purely random garbage.
  for (int iter = 0; iter < 20000; ++iter)
  {
    std::string s(1 + (rng() % 64u), '\0');
    for (char &c : s)
    {
      c = static_cast<char>(rng() & 0xFF);
    }
    decodeBounded(s);
  }
}

// ── task-4.6: CRC-32 known-answer through the trailer path ───────────────────

TEST_CASE("gzip decode verifies the trailer CRC-32 (known answer)",
          "[gzip][decode]")
{
  const std::string plain = "123456789"; // CRC-32 known-answer vector
  REQUIRE(Crc32::compute(plain) == 0xCBF43926u);
  const std::string gz = Gzip::compress(plain);
  auto r = Gzip::decompress(gz, 1u << 20);
  REQUIRE(r.isOk());
  REQUIRE(r.value() == plain);
  REQUIRE(Crc32::compute(r.value()) == 0xCBF43926u);
}

TEST_CASE("gzip decode rejects a valid body whose trailer CRC is wrong",
          "[gzip][decode]")
{
  // Structurally-valid DEFLATE for "123456788", but with the trailer CRC/ISIZE
  // of a different payload -> the integrity check must catch it.
  const std::string realPlain = "123456788";
  const std::string other = "123456789";
  std::string gz = Gzip::compress(realPlain);
  // overwrite the 8-byte trailer with other's CRC + ISIZE
  gz.resize(gz.size() - 8);
  detail::appendLE32(gz, Crc32::compute(other));
  detail::appendLE32(gz, static_cast<std::uint32_t>(other.size()));
  requireMalformed(gz);
}
