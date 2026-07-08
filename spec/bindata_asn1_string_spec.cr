require "./helper"

# Second-pass audit P2 (batch d) — get_string decoded every payload as UTF-8, so
# BMPString (UCS-2 / UTF-16BE) and UniversalString (UCS-4 / UTF-32BE) were
# mis-decoded, and the ASCII-repertoire string types were rejected outright.

private def str_ber(tag : ASN1::BER::UniversalTags, payload : Bytes) : ASN1::BER
  ber = ASN1::BER.new
  ber.tag_class = ASN1::BER::TagClass::Universal
  ber.tag_number = tag
  ber.payload = payload
  ber
end

describe "ASN1::BER#get_string transcoding" do
  it "decodes a BMPString from UTF-16BE" do
    # "Aé" = 00 41 00 E9 in UTF-16BE
    str_ber(ASN1::BER::UniversalTags::BMPString, Bytes[0x00, 0x41, 0x00, 0xE9])
      .get_string.should eq("Aé")
  end

  it "decodes a UniversalString from UTF-32BE" do
    # "Aé" = 00000041 000000E9 in UTF-32BE
    str_ber(ASN1::BER::UniversalTags::UniversalString,
      Bytes[0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0xE9]).get_string.should eq("Aé")
  end

  it "raises a typed error on invalid transcoding input" do
    # lone high surrogate is invalid UTF-16
    expect_raises(ASN1::InvalidPayload) do
      str_ber(ASN1::BER::UniversalTags::BMPString, Bytes[0xD8, 0x00]).get_string
    end
    # truncated UTF-32BE (not a multiple of 4)
    expect_raises(ASN1::InvalidPayload) do
      str_ber(ASN1::BER::UniversalTags::UniversalString, Bytes[0x00, 0x00, 0x41]).get_string
    end
  end

  it "accepts the ASCII-repertoire string types" do
    {ASN1::BER::UniversalTags::NumericString,
     ASN1::BER::UniversalTags::VisibleString,
     ASN1::BER::UniversalTags::GeneralString,
     ASN1::BER::UniversalTags::GraphicString}.each do |tag|
      str_ber(tag, "123".to_slice).get_string.should eq("123")
    end
  end

  it "still decodes the previously-supported types" do
    str_ber(ASN1::BER::UniversalTags::UTF8String, "héllo".to_slice).get_string.should eq("héllo")
    str_ber(ASN1::BER::UniversalTags::PrintableString, "ok".to_slice).get_string.should eq("ok")
  end

  it "rejects T61String / VideotexString (charset not decodable)" do
    expect_raises(ASN1::InvalidTag) { str_ber(ASN1::BER::UniversalTags::T61String, "x".to_slice).get_string }
    expect_raises(ASN1::InvalidTag) { str_ber(ASN1::BER::UniversalTags::VideotexString, "x".to_slice).get_string }
  end

  it "raises on a non-universal element" do
    ber = ASN1::BER.new
    ber.tag_class = ASN1::BER::TagClass::ContextSpecific
    ber.tag_number = 0
    expect_raises(ASN1::InvalidTag) { ber.get_string }
  end
end

describe "ASN1::BER#set_string transcoding" do
  it "encodes a BMPString to UTF-16BE and round-trips" do
    ber = ASN1::BER.new
    ber.set_string("Aé", ASN1::BER::UniversalTags::BMPString)
    ber.payload.should eq(Bytes[0x00, 0x41, 0x00, 0xE9])
    ber.get_string.should eq("Aé")
  end

  it "encodes a UniversalString to UTF-32BE and round-trips" do
    ber = ASN1::BER.new
    ber.set_string("Aé", ASN1::BER::UniversalTags::UniversalString)
    ber.payload.should eq(Bytes[0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, 0xE9])
    ber.get_string.should eq("Aé")
  end

  it "stores UTF-8 bytes for the default UTF8String" do
    ber = ASN1::BER.new
    ber.set_string("héllo")
    ber.payload.should eq("héllo".to_slice)
  end

  it "transcodes when the tag is given as an integer" do
    ber = ASN1::BER.new
    ber.set_string("Aé", ASN1::BER::UniversalTags::BMPString.to_i)
    ber.payload.should eq(Bytes[0x00, 0x41, 0x00, 0xE9])
  end

  it "round-trips an empty BMPString / UniversalString" do
    {ASN1::BER::UniversalTags::BMPString, ASN1::BER::UniversalTags::UniversalString}.each do |tag|
      ber = ASN1::BER.new
      ber.set_string("", tag)
      ber.payload.empty?.should be_true
      ber.get_string.should eq("")
    end
  end
end
