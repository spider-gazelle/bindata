require "./helper"

# Security/robustness: a `length:` / `skip` callback whose result comes from the
# wire must not produce a negative size. A negative `array` length used to read
# zero elements silently; a negative `skip` used to move the cursor backwards
# (re-reading attacker bytes / desyncing the stream). Both must raise a typed
# `BinData::ParseError` instead.

class NegArray < BinData
  endian big
  field n : Int8
  field items : Array(UInt8), length: -> { n.to_i }
end

class NegBytes < BinData
  endian big
  field n : Int8
  field data : Bytes, length: -> { n.to_i }
end

class NegSkip < BinData
  endian big
  field n : Int8
  skip -> { n.to_i }
  field tail : UInt8
end

describe "negative length / skip guard" do
  it "raises on a negative array length instead of silently reading nothing" do
    io = IO::Memory.new(Bytes[0xFF, 0x01, 0x02, 0x03]) # n = -1
    expect_raises(BinData::ParseError) { io.read_bytes(NegArray) }
  end

  it "raises on a negative bytes length" do
    io = IO::Memory.new(Bytes[0xFF, 0x01, 0x02]) # n = -1
    expect_raises(BinData::ParseError) { io.read_bytes(NegBytes) }
  end

  it "raises on a negative skip instead of moving the cursor backwards" do
    io = IO::Memory.new(Bytes[0xFF, 0xAA]) # n = -1
    expect_raises(BinData::ParseError) { io.read_bytes(NegSkip) }
  end

  it "still reads a normal (non-negative) array" do
    io = IO::Memory.new(Bytes[0x02, 0x0A, 0x0B])
    r = io.read_bytes(NegArray)
    r.items.should eq([0x0A_u8, 0x0B_u8])
  end
end
