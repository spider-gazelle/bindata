require "./helper"

# Second-pass audit P0 — confirmed correctness bugs (reproduced against master).
# This file groups the three mechanical fixes shipped together:
#   P0#2  `value:` integer coercion silently truncated instead of raising
#   P0#3  null-terminated String read dropped the last byte when unterminated
#   P0#5  `set_hexstring` silently corrupted its input (odd pad + greedy strip)

# --- P0#2 ----------------------------------------------------------------------

private class CoercedValue < BinData
  endian big
  field n : UInt8, value: -> { 300 }
end

private class FittingValue < BinData
  endian big
  field n : UInt8, value: -> { 42 }
end

private class BoundaryMax < BinData
  endian big
  field n : UInt8, value: -> { 255 }
end

private class BoundaryOver < BinData
  endian big
  field n : UInt8, value: -> { 256 }
end

private class NegativeSigned < BinData
  endian big
  field n : Int8, value: -> { -5 }
end

describe "P0#2 — value: integer coercion" do
  it "raises instead of silently truncating an out-of-range value" do
    # 300 & 0xFF used to write byte 44; an overflowing computed value must fail
    # loudly rather than corrupt the wire.
    expect_raises(BinData::WriteError) { CoercedValue.new.to_slice }
  end

  it "still writes an in-range computed value" do
    FittingValue.new.to_slice.should eq(Bytes[42])
  end

  it "accepts the exact unsigned maximum (255) but rejects one past it (256)" do
    BoundaryMax.new.to_slice.should eq(Bytes[255])
    expect_raises(BinData::WriteError) { BoundaryOver.new.to_slice }
  end

  it "preserves a negative value into a signed field" do
    NegativeSigned.new.to_slice.should eq(Bytes[251]) # -5 two's-complement
  end
end

# --- P0#3 ----------------------------------------------------------------------

private class NullString < BinData
  field text : String
end

describe "P0#3 — null-terminated String read" do
  it "keeps every byte when the stream has no terminator" do
    # "ABC" without a trailing NUL used to decode to "AB".
    NullString.from_slice(Bytes[0x41, 0x42, 0x43]).text.should eq("ABC")
  end

  it "stops at and strips the NUL terminator" do
    str = NullString.from_slice(Bytes[0x41, 0x42, 0x43, 0x00, 0x44])
    str.text.should eq("ABC")
  end

  it "round-trips through write (re-appends the terminator)" do
    str = NullString.new
    str.text = "ABC"
    NullString.from_slice(str.to_slice).text.should eq("ABC")
  end

  it "reads an empty string from an empty stream" do
    NullString.from_slice(Bytes.new(0)).text.should eq("")
  end
end

# --- P0#5 ----------------------------------------------------------------------

describe "P0#5 — set_hexstring" do
  it "decodes a clean even-length hexstring" do
    ber = ASN1::BER.new
    ber.set_hexstring("ABCD")
    ber.get_hexstring.should eq("abcd")
  end

  it "accepts a single leading 0x prefix" do
    ber = ASN1::BER.new
    ber.set_hexstring("0xABCD")
    ber.get_hexstring.should eq("abcd")
  end

  it "accepts an uppercase 0X prefix but rejects a doubled prefix" do
    ber = ASN1::BER.new
    ber.set_hexstring("0XABCD")
    ber.get_hexstring.should eq("abcd")
    # only one prefix is stripped, so the leftover "0x" is invalid hex.
    expect_raises(ArgumentError) { ASN1::BER.new.set_hexstring("0x0xABCD") }
  end

  it "rejects an odd-length hexstring instead of nibble-shifting it" do
    # "ABC" used to become 0x0A 0xBC (every nibble shifted).
    expect_raises(ArgumentError) { ASN1::BER.new.set_hexstring("ABC") }
  end

  it "rejects embedded non-hex instead of silently merging nibbles" do
    # "AB0xCD" used to be stripped to "ABCD"; an interior 0x must not be removed.
    expect_raises(ArgumentError) { ASN1::BER.new.set_hexstring("AB0xCD") }
  end

  it "round-trips raw bytes through get_hexstring" do
    ber = ASN1::BER.new
    ber.set_hexstring("00ff10")
    ber.get_bytes.should eq(Bytes[0x00, 0xFF, 0x10])
  end
end
