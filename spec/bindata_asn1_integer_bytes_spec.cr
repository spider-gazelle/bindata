require "./helper"

# P0#8 — get_integer_bytes returned Bytes[0] for a 0xFF payload (which is -1),
# i.e. it reported a negative value as 0. Per the maintainer's call (#44), the
# contract is the **unsigned magnitude** (big-endian, minimal, leading-zeros
# stripped) of a NON-NEGATIVE INTEGER; a negative payload is rejected.

private def int_bytes(payload : Bytes) : ASN1::BER
  ber = ASN1::BER.new
  ber.tag_number = ASN1::BER::UniversalTags::Integer
  ber.payload = payload
  ber
end

describe "ASN1::BER#get_integer_bytes" do
  it "returns an empty slice for an empty payload" do
    int_bytes(Bytes.new(0)).get_integer_bytes.should eq(Bytes.new(0))
  end

  it "returns a single zero byte for value 0" do
    int_bytes(Bytes[0x00]).get_integer_bytes.should eq(Bytes[0x00])
  end

  it "returns a small positive value verbatim" do
    int_bytes(Bytes[0x7F]).get_integer_bytes.should eq(Bytes[0x7F])
  end

  it "strips the 0x00 sign pad of a high-bit positive value" do
    # 128 is encoded 00 80; its magnitude is 80
    int_bytes(Bytes[0x00, 0x80]).get_integer_bytes.should eq(Bytes[0x80])
  end

  it "strips all leading zero padding (non-minimal input)" do
    int_bytes(Bytes[0x00, 0x00, 0x05]).get_integer_bytes.should eq(Bytes[0x05])
  end

  it "rejects a negative INTEGER (-1)" do
    expect_raises(ASN1::InvalidPayload) { int_bytes(Bytes[0xFF]).get_integer_bytes }
  end

  it "rejects a negative INTEGER (-128)" do
    expect_raises(ASN1::InvalidPayload) { int_bytes(Bytes[0x80]).get_integer_bytes }
  end

  it "raises InvalidTag for a non-INTEGER element" do
    ber = ASN1::BER.new
    ber.set_boolean(true)
    expect_raises(ASN1::InvalidTag) { ber.get_integer_bytes }
  end

  it "round-trips a non-negative value through set_integer" do
    ber = ASN1::BER.new
    ber.set_integer(255)
    ber.get_integer_bytes.should eq(Bytes[0xFF]) # magnitude of 255
  end
end
