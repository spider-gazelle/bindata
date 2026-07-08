require "./helper"
require "bit_array"

# Second-pass audit P2 (batch c) — BIT STRING only supported the zero-unused-bits
# form and had no setter, rejecting valid X.509 (KeyUsage, EC/DSA keys/signatures).
# The first payload byte is the count of unused bits (0..7) in the final byte; the
# remaining bytes hold the data, ASN.1-numbered MSB-first from the first byte.

private def bitstring_ber(payload : Bytes) : ASN1::BER
  ber = ASN1::BER.new
  ber.tag_class = ASN1::BER::TagClass::Universal
  ber.tag_number = ASN1::BER::UniversalTags::BitString
  ber.payload = payload
  ber
end

describe "ASN1::BER BIT STRING" do
  it "reads the data bytes with zero unused bits" do
    ber = bitstring_ber(Bytes[0x00, 0xAB, 0xCD])
    ber.get_bitstring.should eq(Bytes[0xAB, 0xCD])
    ber.bitstring_unused_bits.should eq(0)
  end

  it "reads a BIT STRING with unused bits (no longer raises)" do
    ber = bitstring_ber(Bytes[0x01, 0xB6]) # unused=1, data 0b1011_0110
    ber.get_bitstring.should eq(Bytes[0xB6])
    ber.bitstring_unused_bits.should eq(1)
  end

  it "reads an empty (zero-length) bit string" do
    ber = bitstring_ber(Bytes[0x00])
    ber.get_bitstring.empty?.should be_true
  end

  it "exposes the significant bits as a BitArray (MSB-first)" do
    ber = bitstring_ber(Bytes[0x01, 0xB6]) # 0b1011_0110, drop 1 unused -> 7 bits
    arr = ber.get_bit_array
    arr.size.should eq(7)
    expected = BitArray.new(7)
    [true, false, true, true, false, true, true].each_with_index { |b, i| expected[i] = b }
    arr.should eq(expected)
  end

  it "rejects an out-of-range unused-bit count" do
    expect_raises(ASN1::InvalidPayload) { bitstring_ber(Bytes[0x08, 0xFF]).get_bitstring }
  end

  it "rejects an empty payload (missing the unused-count byte)" do
    expect_raises(ASN1::InvalidPayload) { bitstring_ber(Bytes.new(0)).get_bitstring }
  end

  it "rejects a data-less BIT STRING that declares unused bits" do
    # unused=3 with no data byte would give a negative significant-bit count.
    expect_raises(ASN1::InvalidPayload) { bitstring_ber(Bytes[0x03]).get_bit_array }
  end

  it "reads a multi-byte BitArray across the byte boundary" do
    # data 0xAB 0xCD = 1010_1011 1100_1101, unused=0 -> 16 bits MSB-first
    arr = bitstring_ber(Bytes[0x00, 0xAB, 0xCD]).get_bit_array
    arr.size.should eq(16)
    arr[0].should be_true # 0xAB high bit
    arr[7].should be_true # 0xAB low bit
    arr[8].should be_true # 0xCD high bit
    arr[9].should be_true # second bit of 0xCD (1100_1101)
    arr[10].should be_false
  end

  it "raises on a non-BIT-STRING tag" do
    ber = ASN1::BER.new
    ber.set_integer(5)
    expect_raises(ASN1::InvalidTag) { ber.get_bitstring }
  end

  it "writes a BIT STRING from bytes + unused count" do
    ber = ASN1::BER.new
    ber.set_bitstring(Bytes[0xB6], 1)
    ber.tag_number.should eq(ASN1::BER::UniversalTags::BitString.to_i)
    ber.payload.should eq(Bytes[0x01, 0xB6])
  end

  it "defaults to zero unused bits" do
    ASN1::BER.new.set_bitstring(Bytes[0xAB, 0xCD]).payload.should eq(Bytes[0x00, 0xAB, 0xCD])
  end

  it "rejects an out-of-range unused count on write" do
    expect_raises(ArgumentError) { ASN1::BER.new.set_bitstring(Bytes[0xFF], 8) }
  end

  it "rejects unused bits on an empty payload" do
    expect_raises(ArgumentError) { ASN1::BER.new.set_bitstring(Bytes.new(0), 1) }
  end

  it "round-trips bytes through set_bitstring / get_bitstring" do
    ber = ASN1::BER.new
    ber.set_bitstring(Bytes[0xDE, 0xAD, 0xBE, 0xEF], 4)
    ber.get_bitstring.should eq(Bytes[0xDE, 0xAD, 0xBE, 0xEF])
    ber.bitstring_unused_bits.should eq(4)
  end

  it "round-trips a BitArray through set_bit_array / get_bit_array" do
    bits = BitArray.new(7)
    [true, false, true, true, false, true, true].each_with_index { |b, i| bits[i] = b }
    ber = ASN1::BER.new
    ber.set_bit_array(bits)
    ber.payload.should eq(Bytes[0x01, 0xB6]) # unused=1, 0b1011_0110
    ber.get_bit_array.should eq(bits)
  end

  it "round-trips a multi-byte, non-byte-aligned BitArray (9 bits)" do
    bits = BitArray.new(9)
    bits[0] = true
    bits[8] = true
    ber = ASN1::BER.new
    ber.set_bit_array(bits)
    ber.bitstring_unused_bits.should eq(7) # 2 bytes, 9 bits -> 7 unused
    ber.get_bit_array.should eq(bits)
  end

  it "round-trips an exactly-8-bit BitArray (no unused bits)" do
    bits = BitArray.new(8)
    bits[0] = true
    bits[7] = true
    ber = ASN1::BER.new
    ber.set_bit_array(bits)
    ber.bitstring_unused_bits.should eq(0)
    ber.payload.should eq(Bytes[0x00, 0x81])
    ber.get_bit_array.should eq(bits)
  end
end
