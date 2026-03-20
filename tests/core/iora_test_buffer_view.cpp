// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Tests for BufferView and BufferWriter

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/core/buffer_view.hpp>

#include <cstdint>
#include <vector>

using namespace iora::core;

// ══════════════════════════════════════════════════════════════════════════════
// BufferView Construction
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("BufferView: default construction — empty", "[buffer][view]")
{
  BufferView v;
  REQUIRE(v.data() == nullptr);
  REQUIRE(v.size() == 0);
  REQUIRE(v.empty());
}

TEST_CASE("BufferView: construction from raw ptr+size", "[buffer][view]")
{
  std::uint8_t data[] = {0x01, 0x02, 0x03};
  BufferView v(data, 3);
  REQUIRE(v.data() == data);
  REQUIRE(v.size() == 3);
  REQUIRE_FALSE(v.empty());
}

// ══════════════════════════════════════════════════════════════════════════════
// BufferView Accessors
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("BufferView: operator[]", "[buffer][view]")
{
  std::uint8_t data[] = {0xAA, 0xBB, 0xCC};
  BufferView v(data, 3);
  REQUIRE(v[0] == 0xAA);
  REQUIRE(v[1] == 0xBB);
  REQUIRE(v[2] == 0xCC);
}

TEST_CASE("BufferView: begin/end iterators", "[buffer][view]")
{
  std::uint8_t data[] = {1, 2, 3, 4};
  BufferView v(data, 4);

  // Range-for compatibility
  std::uint8_t sum = 0;
  for (auto byte : v)
  {
    sum += byte;
  }
  REQUIRE(sum == 10);

  // Iterator correctness
  REQUIRE(v.begin() == data);
  REQUIRE(v.end() == data + 4);
}

// ══════════════════════════════════════════════════════════════════════════════
// BufferView Slicing
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("BufferView: subview", "[buffer][view][slice]")
{
  std::uint8_t data[] = {0, 1, 2, 3, 4};
  BufferView v(data, 5);

  auto sub = v.subview(1, 3);
  REQUIRE(sub.size() == 3);
  REQUIRE(sub[0] == 1);
  REQUIRE(sub[2] == 3);
}

TEST_CASE("BufferView: subview with npos default", "[buffer][view][slice]")
{
  std::uint8_t data[] = {0, 1, 2, 3, 4};
  BufferView v(data, 5);

  auto sub = v.subview(2);
  REQUIRE(sub.size() == 3);
  REQUIRE(sub[0] == 2);
}

TEST_CASE("BufferView: subview out of range returns empty", "[buffer][view][slice]")
{
  std::uint8_t data[] = {1, 2};
  BufferView v(data, 2);
  REQUIRE(v.subview(10).empty());
}

TEST_CASE("BufferView: first/last", "[buffer][view][slice]")
{
  std::uint8_t data[] = {1, 2, 3, 4, 5};
  BufferView v(data, 5);

  REQUIRE(v.first(3).size() == 3);
  REQUIRE(v.first(3)[2] == 3);
  REQUIRE(v.last(2).size() == 2);
  REQUIRE(v.last(2)[0] == 4);
}

TEST_CASE("BufferView: removePrefix/removeSuffix", "[buffer][view][slice]")
{
  std::uint8_t data[] = {1, 2, 3, 4, 5};
  BufferView v(data, 5);

  v.removePrefix(2);
  REQUIRE(v.size() == 3);
  REQUIRE(v[0] == 3);

  v.removeSuffix(1);
  REQUIRE(v.size() == 2);
  REQUIRE(v[1] == 4);
}

TEST_CASE("BufferView: removePrefix beyond size yields empty", "[buffer][view][slice]")
{
  std::uint8_t data[] = {1, 2};
  BufferView v(data, 2);
  v.removePrefix(10);
  REQUIRE(v.empty());
}

// ══════════════════════════════════════════════════════════════════════════════
// BufferView Conversion
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("BufferView: toOwned returns independent copy", "[buffer][view]")
{
  std::uint8_t data[] = {0xDE, 0xAD};
  BufferView v(data, 2);
  auto owned = v.toOwned();
  REQUIRE(owned.size() == 2);
  REQUIRE(owned[0] == 0xDE);
  REQUIRE(owned[1] == 0xAD);
  REQUIRE(owned.data() != data);
}

TEST_CASE("BufferView: asStringView roundtrip", "[buffer][view]")
{
  const char* text = "Hello";
  BufferView v(reinterpret_cast<const std::uint8_t*>(text), 5);
  REQUIRE(v.asStringView() == "Hello");
}

// ══════════════════════════════════════════════════════════════════════════════
// BufferView Comparison
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("BufferView: operator== and !=", "[buffer][view]")
{
  std::uint8_t a[] = {1, 2, 3};
  std::uint8_t b[] = {1, 2, 3};
  std::uint8_t c[] = {1, 2, 4};
  std::uint8_t d[] = {1, 2};

  BufferView va(a, 3), vb(b, 3), vc(c, 3), vd(d, 2);

  REQUIRE(va == vb);
  REQUIRE(va != vc);
  REQUIRE(va != vd);

  BufferView empty1, empty2;
  REQUIRE(empty1 == empty2);
}

// ══════════════════════════════════════════════════════════════════════════════
// BufferView Network Readers (unchecked)
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("BufferView: readU8", "[buffer][view][reader]")
{
  std::uint8_t data[] = {0xFF, 0x00, 0x42};
  BufferView v(data, 3);
  REQUIRE(v.readU8(0) == 0xFF);
  REQUIRE(v.readU8(2) == 0x42);
}

TEST_CASE("BufferView: readU16BE/LE", "[buffer][view][reader]")
{
  std::uint8_t data[] = {0x01, 0x02};
  BufferView v(data, 2);
  REQUIRE(v.readU16BE(0) == 0x0102);
  REQUIRE(v.readU16LE(0) == 0x0201);
}

TEST_CASE("BufferView: readU32BE/LE", "[buffer][view][reader]")
{
  std::uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
  BufferView v(data, 4);
  REQUIRE(v.readU32BE(0) == 0x01020304);
  REQUIRE(v.readU32LE(0) == 0x04030201);
}

TEST_CASE("BufferView: readU64BE/LE", "[buffer][view][reader]")
{
  std::uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  BufferView v(data, 8);
  REQUIRE(v.readU64BE(0) == 0x0102030405060708ULL);
  REQUIRE(v.readU64LE(0) == 0x0807060504030201ULL);
}

// ══════════════════════════════════════════════════════════════════════════════
// BufferView Checked Readers
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("BufferView: checked readers — valid offset", "[buffer][view][checked]")
{
  std::uint8_t data[] = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
  BufferView v(data, 8);

  REQUIRE(v.readU8Checked(0).value() == 0xAA);
  REQUIRE(v.readU16BEChecked(0).has_value());
  REQUIRE(v.readU16LEChecked(0).has_value());
  REQUIRE(v.readU32BEChecked(0).has_value());
  REQUIRE(v.readU32LEChecked(0).has_value());
  REQUIRE(v.readU64BEChecked(0).has_value());
  REQUIRE(v.readU64LEChecked(0).has_value());
}

TEST_CASE("BufferView: checked readers — out of bounds returns nullopt", "[buffer][view][checked]")
{
  std::uint8_t data[] = {0x01};
  BufferView v(data, 1);

  REQUIRE_FALSE(v.readU8Checked(1).has_value());
  REQUIRE_FALSE(v.readU16BEChecked(0).has_value());
  REQUIRE_FALSE(v.readU16LEChecked(0).has_value());
  REQUIRE_FALSE(v.readU32BEChecked(0).has_value());
  REQUIRE_FALSE(v.readU32LEChecked(0).has_value());
  REQUIRE_FALSE(v.readU64BEChecked(0).has_value());
  REQUIRE_FALSE(v.readU64LEChecked(0).has_value());
}

TEST_CASE("BufferView: checked readers — boundary exact", "[buffer][view][checked]")
{
  std::uint8_t data[] = {0x01, 0x02};
  BufferView v(data, 2);

  // Exactly fits U16 at offset 0
  REQUIRE(v.readU16BEChecked(0).has_value());
  // Does NOT fit U16 at offset 1 (only 1 byte left)
  REQUIRE_FALSE(v.readU16BEChecked(1).has_value());
}

TEST_CASE("BufferView: checked readers — empty buffer", "[buffer][view][checked]")
{
  BufferView v;
  REQUIRE_FALSE(v.readU8Checked(0).has_value());
}

// ══════════════════════════════════════════════════════════════════════════════
// BufferWriter
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("BufferWriter: sequential writes", "[buffer][writer]")
{
  std::uint8_t buf[20] = {};
  BufferWriter w(buf, sizeof(buf));

  REQUIRE(w.bytesWritten() == 0);
  REQUIRE(w.remaining() == 20);

  REQUIRE(w.writeU8(0xFF));
  REQUIRE(w.bytesWritten() == 1);

  REQUIRE(w.writeU16BE(0x0102));
  REQUIRE(w.bytesWritten() == 3);

  REQUIRE(w.writeU32BE(0x03040506));
  REQUIRE(w.bytesWritten() == 7);

  REQUIRE(w.writeU64BE(0x0708090A0B0C0D0EULL));
  REQUIRE(w.bytesWritten() == 15);

  REQUIRE(w.remaining() == 5);
}

TEST_CASE("BufferWriter: LE writes", "[buffer][writer]")
{
  std::uint8_t buf[8] = {};
  BufferWriter w(buf, sizeof(buf));

  REQUIRE(w.writeU16LE(0x0102));
  REQUIRE(buf[0] == 0x02);
  REQUIRE(buf[1] == 0x01);

  REQUIRE(w.writeU32LE(0x03040506));
  REQUIRE(buf[2] == 0x06);
  REQUIRE(buf[3] == 0x05);
}

TEST_CASE("BufferWriter: append BufferView", "[buffer][writer]")
{
  std::uint8_t buf[10] = {};
  BufferWriter w(buf, sizeof(buf));

  std::uint8_t src[] = {0xAA, 0xBB, 0xCC};
  REQUIRE(w.append(BufferView(src, 3)));
  REQUIRE(w.bytesWritten() == 3);
  REQUIRE(buf[0] == 0xAA);
  REQUIRE(buf[2] == 0xCC);
}

TEST_CASE("BufferWriter: append raw ptr+len", "[buffer][writer]")
{
  std::uint8_t buf[10] = {};
  BufferWriter w(buf, sizeof(buf));

  std::uint8_t src[] = {0x11, 0x22};
  REQUIRE(w.append(src, 2));
  REQUIRE(w.bytesWritten() == 2);
  REQUIRE(buf[0] == 0x11);
}

TEST_CASE("BufferWriter: writeU64BE/LE content verification", "[buffer][writer]")
{
  std::uint8_t buf[16] = {};
  BufferWriter w(buf, sizeof(buf));

  REQUIRE(w.writeU64BE(0x0102030405060708ULL));
  BufferView v(buf, 8);
  REQUIRE(v.readU64BE(0) == 0x0102030405060708ULL);

  REQUIRE(w.writeU64LE(0x0102030405060708ULL));
  BufferView v2(buf + 8, 8);
  REQUIRE(v2.readU64LE(0) == 0x0102030405060708ULL);
}

TEST_CASE("BufferWriter: overflow for U32/U64/append", "[buffer][writer]")
{
  std::uint8_t buf[3] = {};
  BufferWriter w(buf, sizeof(buf));

  REQUIRE_FALSE(w.writeU32BE(0x01020304));
  REQUIRE(w.bytesWritten() == 0);

  REQUIRE_FALSE(w.writeU64BE(0x0102030405060708ULL));
  REQUIRE(w.bytesWritten() == 0);

  std::uint8_t src[] = {1, 2, 3, 4};
  REQUIRE_FALSE(w.append(src, 4));
  REQUIRE(w.bytesWritten() == 0);

  // But 3 bytes fits
  REQUIRE(w.append(src, 3));
  REQUIRE(w.bytesWritten() == 3);
}

TEST_CASE("BufferWriter: overflow returns false", "[buffer][writer]")
{
  std::uint8_t buf[2] = {0x00, 0x00};
  BufferWriter w(buf, sizeof(buf));

  REQUIRE(w.writeU8(0xFF));
  REQUIRE(w.bytesWritten() == 1);

  // Only 1 byte left, U16 needs 2
  REQUIRE_FALSE(w.writeU16BE(0x0102));
  REQUIRE(w.bytesWritten() == 1);  // cursor did not advance
  REQUIRE(buf[1] == 0x00);         // buffer unchanged
}

TEST_CASE("BufferWriter: written() returns correct view", "[buffer][writer]")
{
  std::uint8_t buf[10] = {};
  BufferWriter w(buf, sizeof(buf));

  w.writeU8(0xAA);
  w.writeU16BE(0xBBCC);

  auto view = w.written();
  REQUIRE(view.size() == 3);
  REQUIRE(view[0] == 0xAA);
  REQUIRE(view.readU16BE(1) == 0xBBCC);
}

// ══════════════════════════════════════════════════════════════════════════════
// Integration: Write then Read
// ══════════════════════════════════════════════════════════════════════════════

TEST_CASE("Integration: write with BufferWriter, read with BufferView", "[buffer][integration]")
{
  std::uint8_t buf[32] = {};
  BufferWriter w(buf, sizeof(buf));

  w.writeU8(0x42);
  w.writeU16BE(0x1234);
  w.writeU32BE(0xDEADBEEF);
  w.writeU64BE(0x0102030405060708ULL);

  BufferView v = w.written();
  REQUIRE(v.size() == 15);
  REQUIRE(v.readU8(0) == 0x42);
  REQUIRE(v.readU16BE(1) == 0x1234);
  REQUIRE(v.readU32BE(3) == 0xDEADBEEF);
  REQUIRE(v.readU64BE(7) == 0x0102030405060708ULL);
}
