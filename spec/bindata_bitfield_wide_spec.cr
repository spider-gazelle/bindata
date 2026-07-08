require "./helper"

# P4/P5 — the 32/64/128-bit branches of BitField#read decode a value from the
# buffer. These round-trip characterisation specs pin their behaviour (incl. the
# 128-bit branch and the short-tail padding path, both previously uncovered) so
# the slice-decode optimisation is provably behaviour-preserving.

private class Wide128 < BinData
  endian big
  bit_field do
    bits 128, :big
  end
end

# `tail` (24 bits, the 17..32 branch) is read after `head` consumes one byte, so
# only 3 bytes remain in the buffer — exercising the "buffer shorter than the
# decoded type" padding path.
private class ShortTail < BinData
  endian big
  bit_field do
    bits 8, :head
    bits 24, :tail
  end
end

# A 64-bit field read from a full 8-byte buffer (the 33..64 branch).
private class Wide64 < BinData
  endian big
  bit_field do
    bits 64, :big
  end
end

# `head` consumes one byte so the 56-bit `tail` (33..64 branch) reads from a
# 7-byte remainder — the short-tail padding path for the 64-bit branch.
private class ShortTail64 < BinData
  endian big
  bit_field do
    bits 8, :head
    bits 56, :tail
  end
end

# Same, for the 65..128 branch: a 120-bit tail read from a 15-byte remainder.
private class ShortTail128 < BinData
  endian big
  bit_field do
    bits 8, :head
    bits 120, :tail
  end
end

describe "BitField wide-field decode" do
  it "round-trips a 128-bit field" do
    w = Wide128.new
    w.big = 0x0102030405060708090A0B0C0D0E0F10_u128
    bytes = w.to_slice
    bytes.size.should eq(16)
    Wide128.from_slice(bytes).big.should eq(0x0102030405060708090A0B0C0D0E0F10_u128)
  end

  it "round-trips a 64-bit field" do
    w = Wide64.new
    w.big = 0xDEADBEEFCAFEF00D_u64
    Wide64.from_slice(w.to_slice).big.should eq(0xDEADBEEFCAFEF00D_u64)
  end

  it "decodes a 24-bit field from a short (padded) buffer tail" do
    s = ShortTail.new
    s.head = 0xAB_u8
    s.tail = 0x123456_u32
    bytes = s.to_slice
    bytes.should eq(Bytes[0xAB, 0x12, 0x34, 0x56])

    rt = ShortTail.from_slice(bytes)
    rt.head.should eq(0xAB_u8)
    rt.tail.should eq(0x123456_u32)
  end

  it "decodes a 56-bit field from a short (padded) buffer tail" do
    s = ShortTail64.new
    s.head = 0xAB_u8
    s.tail = 0x00112233445566_u64
    rt = ShortTail64.from_slice(s.to_slice)
    rt.head.should eq(0xAB_u8)
    rt.tail.should eq(0x00112233445566_u64)
  end

  it "decodes a 120-bit field from a short (padded) buffer tail" do
    s = ShortTail128.new
    s.head = 0xAB_u8
    s.tail = 0x0102030405060708090A0B0C0D0E0F_u128
    rt = ShortTail128.from_slice(s.to_slice)
    rt.head.should eq(0xAB_u8)
    rt.tail.should eq(0x0102030405060708090A0B0C0D0E0F_u128)
  end
end
