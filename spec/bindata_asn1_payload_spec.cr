require "./helper"

# Audit Tier 1 — typed errors on malformed input. `get_boolean` / `get_bitstring`
# indexed `@payload[0]` without a bounds check, raising `IndexError` on an empty
# payload instead of a meaningful, typed ASN.1 error.

describe "ASN1::BER empty payloads" do
  it "raises a typed error on an empty BOOLEAN payload" do
    ber = ASN1::BER.new
    ber.tag_number = ASN1::BER::UniversalTags::Boolean
    ber.payload = Bytes.new(0)
    expect_raises(ASN1::InvalidPayload) { ber.get_boolean }
  end

  it "raises a typed error on an empty BIT STRING payload" do
    ber = ASN1::BER.new
    ber.tag_number = ASN1::BER::UniversalTags::BitString
    ber.payload = Bytes.new(0)
    expect_raises(ASN1::InvalidPayload) { ber.get_bitstring }
  end

  it "prefers InvalidTag over InvalidPayload for a wrong-tag empty payload" do
    ber = ASN1::BER.new
    ber.tag_number = ASN1::BER::UniversalTags::Integer # not Boolean
    ber.payload = Bytes.new(0)
    expect_raises(ASN1::InvalidTag) { ber.get_boolean }
  end

  it "is catchable via the ASN1::Error parent" do
    ber = ASN1::BER.new
    ber.tag_number = ASN1::BER::UniversalTags::Boolean
    ber.payload = Bytes.new(0)
    expect_raises(ASN1::Error) { ber.get_boolean }
  end

  it "still reads valid BOOLEAN and BIT STRING payloads" do
    ber = ASN1::BER.new
    ber.set_boolean(true)
    ber.get_boolean.should eq(true)

    bs = IO::Memory.new(Bytes[0x03, 0x02, 0x0, 0x1]).read_bytes(ASN1::BER)
    bs.get_bitstring.should eq(Bytes[0x1])
  end
end
