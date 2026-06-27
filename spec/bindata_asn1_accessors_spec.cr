require "./helper"

private def int_bytes(payload : Bytes)
  ber = ASN1::BER.new
  ber.tag_number = ASN1::BER::UniversalTags::Integer
  ber.payload = payload
  ber.get_integer_bytes
end

# Characterisation coverage for ASN.1 typed accessors that previously had no
# direct specs: hexstring, raw bytes, get_integer_bytes branches, sequence?,
# get_string tag handling, set_string tag override, and children= edges.
describe "ASN1::BER typed accessors" do
  describe "hexstring" do
    it "round-trips a hexstring" do
      ber = ASN1::BER.new
      ber.set_hexstring("00ff")
      ber.tag_number.should eq(ASN1::BER::UniversalTags::OctetString.to_i)
      ber.get_hexstring.should eq("00ff")
    end

    it "strips a single leading 0x prefix" do
      ber = ASN1::BER.new
      ber.set_hexstring("0xABCD")
      ber.get_hexstring.should eq("abcd")
    end

    it "rejects interior non-hex instead of silently stripping it" do
      # A separator inside the string (e.g. "AB:CD") used to be stripped, merging
      # nibbles; it must now be rejected.
      expect_raises(ArgumentError) { ASN1::BER.new.set_hexstring("AB:CD") }
    end

    it "rejects an odd-length hexstring instead of nibble-shifting it" do
      expect_raises(ArgumentError) { ASN1::BER.new.set_hexstring("ABC") }
    end
  end

  describe "raw bytes" do
    it "round-trips raw bytes and tags them OctetString" do
      ber = ASN1::BER.new
      ber.set_bytes(Bytes[1, 2, 3])
      ber.tag_number.should eq(ASN1::BER::UniversalTags::OctetString.to_i)
      ber.get_bytes.should eq(Bytes[1, 2, 3])
    end
  end

  describe "get_integer_bytes" do
    it "returns an empty slice for an empty payload" do
      int_bytes(Bytes.new(0)).should eq(Bytes.new(0))
    end

    it "collapses a single 0x00 or 0xFF sign byte to a single zero byte" do
      int_bytes(Bytes[0x00]).should eq(Bytes[0])
      int_bytes(Bytes[0xFF]).should eq(Bytes[0])
    end

    it "drops a leading 0x00 pad byte" do
      int_bytes(Bytes[0x00, 0xFB]).should eq(Bytes[0xFB])
    end

    it "passes other payloads through unchanged" do
      int_bytes(Bytes[0x05]).should eq(Bytes[0x05])
      int_bytes(Bytes[0x12, 0x34]).should eq(Bytes[0x12, 0x34])
    end
  end

  describe "sequence?" do
    it "is true for a constructed universal Sequence" do
      ber = ASN1::BER.new
      ber.tag_number = ASN1::BER::UniversalTags::Sequence
      ber.constructed = true
      ber.sequence?.should be_true
    end

    it "is false for a primitive Integer" do
      ber = ASN1::BER.new
      ber.tag_number = ASN1::BER::UniversalTags::Integer
      ber.sequence?.should be_false
    end

    it "is false for a non-universal tag" do
      ber = ASN1::BER.new
      ber.tag_class = ASN1::BER::TagClass::Application
      ber.constructed = true
      ber.sequence?.should be_false
    end
  end

  describe "get_string" do
    it "accepts any of the universal string tags" do
      {ASN1::BER::UniversalTags::OctetString,
       ASN1::BER::UniversalTags::PrintableString,
       ASN1::BER::UniversalTags::IA5String}.each do |tag|
        ber = ASN1::BER.new
        ber.tag_number = tag
        ber.payload = "hi".to_slice
        ber.get_string.should eq("hi")
      end
    end

    it "raises InvalidTag on a non-string tag" do
      ber = ASN1::BER.new
      ber.tag_number = ASN1::BER::UniversalTags::Integer
      ber.payload = "hi".to_slice
      expect_raises(ASN1::InvalidTag) { ber.get_string }
    end
  end

  describe "tag overrides" do
    it "honours a tag_class override on set_string" do
      ber = ASN1::BER.new
      ber.set_string("x", tag_class: ASN1::BER::TagClass::ContextSpecific)
      ber.tag_class.should eq(ASN1::BER::TagClass::ContextSpecific)
      String.new(ber.payload).should eq("x")
    end
  end

  describe "children=" do
    it "marks the element constructed and empties the payload for no children" do
      ber = ASN1::BER.new
      ber.children = [] of ASN1::BER
      ber.constructed.should be_true
      ber.payload.empty?.should be_true
      ber.children.empty?.should be_true
    end
  end
end
