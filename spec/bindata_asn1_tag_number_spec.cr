require "./helper"

# Second-pass audit P0#1 — `BER#tag_number=` stored the value straight into the
# 5-bit identifier field, so a tag of 32..255 was silently truncated to its low
# 5 bits (50 -> 18 on the wire) and a value >= 256 leaked a raw `OverflowError`.
# The 5-bit field can only hold 0..30 (31 is the reserved high-tag-number escape;
# tags >= 31 need the extended continuation-byte form, which this accessor does
# not emit). Out-of-range values now raise a typed `ASN1::InvalidTag`.

describe "ASN1::BER#tag_number=" do
  it "accepts the in-range maximum (30) and round-trips on the wire" do
    ber = ASN1::BER.new
    ber.tag_class = ASN1::BER::TagClass::Application
    ber.tag_number = 30
    ber.tag_number.should eq(30)

    rt = IO::Memory.new(ber.to_slice).read_bytes(ASN1::BER)
    rt.tag_number.should eq(30)
  end

  it "accepts the in-range minimum (0)" do
    ber = ASN1::BER.new
    ber.tag_number = 0
    ber.tag_number.should eq(0)
  end

  it "accepts every universal tag (all <= 30)" do
    ber = ASN1::BER.new
    ber.tag_number = ASN1::BER::UniversalTags::BMPString # 30, the largest
    ber.tag_number.should eq(30)
  end

  it "rejects a tag that would truncate to 5 bits instead of silently corrupting" do
    # 50 & 0b11111 == 18 used to be written to the wire.
    expect_raises(ASN1::InvalidTag) { ASN1::BER.new.tag_number = 50 }
  end

  it "rejects the reserved high-tag-number escape (31)" do
    expect_raises(ASN1::InvalidTag) { ASN1::BER.new.tag_number = 31 }
  end

  it "rejects a value >= 256 with a typed error instead of OverflowError" do
    expect_raises(ASN1::InvalidTag) { ASN1::BER.new.tag_number = 300 }
  end

  it "rejects a negative tag number" do
    expect_raises(ASN1::InvalidTag) { ASN1::BER.new.tag_number = -1 }
  end
end
