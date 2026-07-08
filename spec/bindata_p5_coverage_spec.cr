require "./helper"

# Second-pass audit P5 — characterisation coverage for DSL paths and a couple of
# ASN.1 setters that had no direct specs. These describe current behaviour; a
# failure here means a real defect to fix, not just a missing test.

private enum P5Color : UInt8
  Red
  Green
  Blue
end

private class P5Bool < BinData
  bit_field do
    bool flag = true
    bits 7, :pad
  end
end

private class P5Wide128 < BinData
  endian big
  bit_field do
    bits 128, :val
  end
end

private class P5Ints < BinData
  endian big
  field a : Int128
  field b : UInt128
end

private class P5Enum < BinData
  endian big
  field colour : P5Color = P5Color::Red
end

private class P5VarArray < BinData
  endian big
  field count : UInt8
  field items : Array(UInt8), read_next: -> { items.size < count }
end

private class P5Net < BinData
  endian network
  field val : UInt16
end

private class P5System < BinData
  endian system
  field val : UInt32
end

private class P5FloatLE < BinData
  endian big
  field f : Float32, endian: IO::ByteFormat::LittleEndian
end

private class P5Group < BinData
  endian big
  group :g, verify: -> { g.x == 5_u8 } do
    field x : UInt8
  end
end

describe "P5 DSL coverage" do
  it "honours a bool default of true" do
    P5Bool.new.flag.should be_true
  end

  it "round-trips a 128-bit bit_field" do
    obj = P5Wide128.new
    obj.val = 0x0102030405060708090A0B0C0D0E0F10_u128
    P5Wide128.from_slice(obj.to_slice).val.should eq(0x0102030405060708090A0B0C0D0E0F10_u128)
  end

  it "round-trips Int128 / UInt128 fields" do
    obj = P5Ints.new
    obj.a = -170141183460469231731687303715884105728_i128 # Int128::MIN
    obj.b = 340282366920938463463374607431768211455_u128  # UInt128::MAX
    rt = P5Ints.from_slice(obj.to_slice)
    rt.a.should eq(-170141183460469231731687303715884105728_i128)
    rt.b.should eq(340282366920938463463374607431768211455_u128)
  end

  it "reads a valid enum value" do
    P5Enum.from_slice(Bytes[0x02]).colour.should eq(P5Color::Blue)
  end

  it "raises on an invalid enum value" do
    expect_raises(BinData::ParseError) { P5Enum.from_slice(Bytes[0x63]) } # 99
  end

  it "reads an empty variable_array" do
    P5VarArray.from_slice(Bytes[0x00]).items.empty?.should be_true
  end

  it "reads a populated variable_array" do
    P5VarArray.from_slice(Bytes[0x03, 0x0A, 0x0B, 0x0C]).items.should eq([0x0A_u8, 0x0B_u8, 0x0C_u8])
  end

  it "treats endian network as big-endian" do
    obj = P5Net.new
    obj.val = 0x0102_u16
    obj.to_slice.should eq(Bytes[0x01, 0x02])
  end

  it "round-trips with endian system" do
    obj = P5System.new
    obj.val = 0xDEADBEEF_u32
    P5System.from_slice(obj.to_slice).val.should eq(0xDEADBEEF_u32)
  end

  it "honours a per-field little-endian override on a Float" do
    obj = P5FloatLE.new
    obj.f = 1.0_f32
    # 1.0f little-endian = 00 00 80 3F
    obj.to_slice.should eq(Bytes[0x00, 0x00, 0x80, 0x3F])
    P5FloatLE.from_slice(obj.to_slice).f.should eq(1.0_f32)
  end

  it "passes a group verify when the callback holds" do
    P5Group.from_slice(Bytes[0x05]).g.x.should eq(5_u8)
  end

  it "raises when a group verify fails" do
    expect_raises(BinData::VerificationException) { P5Group.from_slice(Bytes[0x03]) }
  end
end

describe "P5 ASN.1 set_integer coverage" do
  it "round-trips zero" do
    ber = ASN1::BER.new
    ber.set_integer(0)
    ber.payload.should eq(Bytes[0x00])
    ber.get_integer.should eq(0)
  end

  it "encodes from raw bytes (non-to_io path)" do
    ber = ASN1::BER.new
    ber.set_integer(Bytes[0x7F])
    ber.get_integer.should eq(0x7F)
  end
end
