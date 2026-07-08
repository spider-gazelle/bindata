require "./helper"

# P5 (batch b) — remaining coverage: error-model wrapping, nilable write, and the
# bit_field onlyif/verify callbacks + a deprecated width macro.

private class P5TwoFields < BinData
  endian big
  field a : UInt8
  field b : UInt32
end

private class P5Nilable < BinData
  endian big
  field a : UInt8?
end

private class P5BitOnlyif < BinData
  endian big
  field flag : UInt8
  bit_field onlyif: -> { flag == 1_u8 } do
    bits 8, :data
  end
end

private class P5BitVerify < BinData
  endian big
  bit_field verify: -> { data == 5_u8 } do
    bits 8, :data
  end
end

describe "P5b error-model coverage" do
  it "wraps an EOF mid-field in ParseError with the field name and cause" do
    ex = expect_raises(BinData::ParseError) { P5TwoFields.from_slice(Bytes[0x01, 0x02]) }
    ex.field.should eq("b")
    ex.cause.should be_a(IO::EOFError)
  end

  it "raises WriteError (NilAssertionError cause) when writing a nil union field" do
    obj = P5Nilable.new # @a defaults to nil
    ex = expect_raises(BinData::WriteError) { obj.to_slice }
    ex.cause.should be_a(NilAssertionError)
  end
end

describe "P5b bit_field callbacks" do
  it "skips a bit_field when onlyif is false" do
    obj = P5BitOnlyif.from_slice(Bytes[0x00]) # flag != 1 -> bitfield skipped
    obj.flag.should eq(0_u8)
    obj.data.should eq(0_u8) # default, not read
  end

  it "reads a bit_field when onlyif is true" do
    obj = P5BitOnlyif.from_slice(Bytes[0x01, 0xAB])
    obj.data.should eq(0xAB_u8)
  end

  it "passes a bit_field verify that holds" do
    P5BitVerify.from_slice(Bytes[0x05]).data.should eq(5_u8)
  end

  it "raises when a bit_field verify fails" do
    expect_raises(BinData::VerificationException) { P5BitVerify.from_slice(Bytes[0x03]) }
  end
end
