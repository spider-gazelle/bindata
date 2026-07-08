require "./helper"

# Second-pass audit P2 (protocol accessors, batch a — small non-breaking):
#   - NULL had no accessor (set_null / null?)
#   - get_integer was unusable with a non-universal check_class (SNMP context tags)
#   - a single-arc OID was silently expanded to two arcs on encode

describe "ASN1::BER NULL" do
  it "writes a NULL element" do
    ber = ASN1::BER.new
    ber.set_null
    ber.null?.should be_true
    ber.to_slice.should eq(Bytes[0x05, 0x00])
  end

  it "recognises a decoded NULL" do
    IO::Memory.new(Bytes[0x05, 0x00]).read_bytes(ASN1::BER).null?.should be_true
  end

  it "is false for a non-NULL element" do
    ber = ASN1::BER.new
    ber.set_integer(5)
    ber.null?.should be_false
  end

  it "is false for a NULL tag carrying a (malformed) payload" do
    ber = ASN1::BER.new
    ber.tag_class = ASN1::BER::TagClass::Universal
    ber.tag_number = ASN1::BER::UniversalTags::Null
    ber.payload = Bytes[0xFF]
    ber.null?.should be_false
  end

  it "is false for a constructed NULL tag (NULL must be primitive)" do
    ber = ASN1::BER.new
    ber.tag_class = ASN1::BER::TagClass::Universal
    ber.tag_number = ASN1::BER::UniversalTags::Null
    ber.constructed = true
    ber.null?.should be_false
  end
end

describe "ASN1::BER#get_integer with a non-universal class" do
  it "decodes a context-tagged integer (e.g. an SNMP Counter)" do
    ber = ASN1::BER.new
    ber.tag_class = ASN1::BER::TagClass::ContextSpecific
    ber.tag_number = 1 # context [1]
    ber.payload = Bytes[0x2A]
    ber.get_integer(check_class: ASN1::BER::TagClass::ContextSpecific).should eq(42)
  end

  it "still validates the tag for the universal default" do
    ber = ASN1::BER.new
    ber.set_boolean(true) # universal BOOLEAN, not an INTEGER
    expect_raises(ASN1::InvalidTag) { ber.get_integer }
  end

  it "rejects a mismatched class" do
    ber = ASN1::BER.new
    ber.set_integer(42) # universal
    expect_raises(ASN1::InvalidTag) { ber.get_integer(check_class: ASN1::BER::TagClass::ContextSpecific) }
  end

  it "decodes a negative application-tagged integer" do
    ber = ASN1::BER.new
    ber.tag_class = ASN1::BER::TagClass::Application
    ber.tag_number = 0
    ber.payload = Bytes[0xFF] # two's-complement -1
    ber.get_integer(check_class: ASN1::BER::TagClass::Application).should eq(-1)
  end
end

describe "ASN1::BER#set_object_id single arc" do
  it "rejects a single-arc OID instead of silently expanding it" do
    # "2" used to encode as OID "2.0" (lossy).
    expect_raises(ASN1::InvalidObjectId) { ASN1::BER.new.set_object_id("2") }
  end

  it "still round-trips a normal OID" do
    ber = ASN1::BER.new
    ber.set_object_id("1.2.840.113549.1.1.1")
    ber.get_object_id.should eq("1.2.840.113549.1.1.1")
  end

  it "accepts a minimal two-arc OID" do
    ber = ASN1::BER.new
    ber.set_object_id("1.2")
    ber.get_object_id.should eq("1.2")
  end
end
