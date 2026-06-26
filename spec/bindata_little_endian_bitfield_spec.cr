require "./helper"

class LeBits < BinData
  endian little
  bit_field do
    bits 4, :a
    bits 12, :b
  end
end

class BeBits < BinData
  endian big
  bit_field do
    bits 4, :a
    bits 12, :b
  end
end

class OverrideBits < BinData
  endian big
  bit_field endian: :little do
    bits 4, :a
    bits 12, :b
  end
end

# `endian: :big` override inside a little-endian class
class ReverseOverrideBits < BinData
  endian little
  bit_field endian: :big do
    bits 4, :a
    bits 12, :b
  end
end

# odd, 3-byte bitfield with fields crossing several byte boundaries
class WideLeBits < BinData
  endian little
  bit_field do
    bits 4, :a
    bits 5, :b
    bits 15, :c
  end
end

class WideBeBits < BinData
  endian big
  bit_field do
    bits 4, :a
    bits 5, :b
    bits 15, :c
  end
end

describe "little-endian bit fields" do
  it "byte-reverses the bitfield and round-trips" do
    le = LeBits.new
    le.a = 0xA_u8
    le.b = 0x123_u16

    io = IO::Memory.new
    le.write(io)
    bytes = io.to_slice

    # same field values, big-endian, for comparison
    be = BeBits.new
    be.a = 0xA_u8
    be.b = 0x123_u16
    be_bytes = IO::Memory.new.tap { |m| be.write(m) }.to_slice

    bytes.should eq(be_bytes.dup.reverse!) # little-endian wire = byte-reverse of big-endian

    rt = IO::Memory.new(bytes).read_bytes(LeBits)
    rt.a.should eq(0xA_u8)
    rt.b.should eq(0x123_u16)
  end

  it "honors a per-bit_field endian override" do
    o = OverrideBits.new
    o.a = 0xA_u8
    o.b = 0x123_u16
    io = IO::Memory.new
    o.write(io)

    rt = IO::Memory.new(io.to_slice).read_bytes(OverrideBits)
    rt.a.should eq(0xA_u8)
    rt.b.should eq(0x123_u16)

    # same as a LeBits little-endian bitfield, not the big-endian class default
    le_bytes = IO::Memory.new.tap { |m| LeBits.new.tap { |x| x.a = 0xA_u8; x.b = 0x123_u16 }.write(m) }.to_slice
    io.to_slice.should eq(le_bytes)
  end

  it "honors a big-endian override inside a little-endian class" do
    o = ReverseOverrideBits.new
    o.a = 0xA_u8
    o.b = 0x123_u16
    bytes = IO::Memory.new.tap { |m| o.write(m) }.to_slice

    # forced big-endian: identical to the BeBits class, not byte-reversed
    be_bytes = IO::Memory.new.tap { |m| BeBits.new.tap { |x| x.a = 0xA_u8; x.b = 0x123_u16 }.write(m) }.to_slice
    bytes.should eq(be_bytes)

    rt = IO::Memory.new(bytes).read_bytes(ReverseOverrideBits)
    rt.a.should eq(0xA_u8)
    rt.b.should eq(0x123_u16)
  end

  it "byte-reverses a 3-byte bitfield with fields crossing boundaries" do
    le = WideLeBits.new
    le.a = 0xA_u8
    le.b = 0x15_u8
    le.c = 0x1234_u16
    bytes = IO::Memory.new.tap { |m| le.write(m) }.to_slice

    be_bytes = IO::Memory.new.tap { |m| WideBeBits.new.tap { |x| x.a = 0xA_u8; x.b = 0x15_u8; x.c = 0x1234_u16 }.write(m) }.to_slice
    bytes.should eq(be_bytes.dup.reverse!)

    rt = IO::Memory.new(bytes).read_bytes(WideLeBits)
    rt.a.should eq(0xA_u8)
    rt.b.should eq(0x15_u8)
    rt.c.should eq(0x1234_u16)
  end
end
