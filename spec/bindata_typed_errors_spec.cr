require "./helper"

# Audit Tier 1.3 — bare `raise "string"` replaced with typed errors:
# BitField DSL misuse -> ArgumentError; ASN.1 errors -> the ASN1::Error hierarchy.

describe "typed errors" do
  it "raises ArgumentError for a bit field larger than 128 bits" do
    expect_raises(ArgumentError) { BinData::BitField.new.bits(129, :x) }
  end

  it "raises ArgumentError when a bit field is not byte-aligned" do
    bf = BinData::BitField.new
    bf.bits 5, :x
    expect_raises(ArgumentError) { bf.apply }
  end

  it "raises InvalidTag when asking for the universal tag of a non-universal element" do
    ber = ASN1::BER.new
    ber.tag_class = ASN1::BER::TagClass::Application
    expect_raises(ASN1::InvalidTag) { ber.tag }
  end

  it "raises InvalidPayload for a BIT STRING with an out-of-range unused-bit count" do
    # Unused-bit counts 0..7 are now supported; a count > 7 is malformed.
    ber = ASN1::BER.new
    ber.tag_number = ASN1::BER::UniversalTags::BitString
    ber.payload = Bytes[0x08, 0xF0] # first byte = 8 unused bits (max is 7)
    expect_raises(ASN1::InvalidPayload) { ber.get_bitstring }
  end

  it "surfaces a too-long length indicator as a typed InvalidLength cause" do
    # The check fires inside the `long_bytes` length proc, which runs during the
    # generated read — so it is wrapped in ParseError with InvalidLength as cause.
    # 0x85 = long form announcing 5 length bytes (> 4)
    io = IO::Memory.new(Bytes[0x85, 0, 0, 0, 0, 0])
    ex = expect_raises(BinData::ParseError) { io.read_bytes(ASN1::BER::Length) }
    ex.cause.should be_a(ASN1::InvalidLength)
  end
end
