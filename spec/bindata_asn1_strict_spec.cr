require "./helper"

# Item 2 — opt-in `strict` (DER) mode. Default is the current BER-permissive
# behaviour; when `strict` is set, non-canonical encodings are rejected.

private def read_strict(bytes : Bytes) : ASN1::BER
  ber = ASN1::BER.new
  ber.strict = true
  ber.read(IO::Memory.new(bytes))
  ber
end

private def strict_ber(tag : ASN1::BER::UniversalTags, payload : Bytes) : ASN1::BER
  ber = ASN1::BER.new
  ber.strict = true
  ber.tag_class = ASN1::BER::TagClass::Universal
  ber.tag_number = tag
  ber.payload = payload
  ber
end

describe "ASN1::BER strict mode" do
  it "defaults to non-strict (unchanged behaviour)" do
    ASN1::BER.new.strict?.should be_false
    # a non-minimal length parses fine when not strict
    IO::Memory.new(Bytes[0x04, 0x81, 0x01, 0x41]).read_bytes(ASN1::BER).payload.should eq(Bytes[0x41])
  end

  describe "length" do
    it "accepts a minimal short-form length" do
      read_strict(Bytes[0x04, 0x01, 0x41]).payload.should eq(Bytes[0x41])
    end

    it "accepts a minimal long-form length (>= 128)" do
      read_strict(Bytes[0x04, 0x81, 0x80] + Bytes.new(128, 0x41_u8)).payload.size.should eq(128)
    end

    it "rejects a long-form length that fits short form" do
      expect_raises(ASN1::Error) { read_strict(Bytes[0x04, 0x81, 0x01, 0x41]) }
    end

    it "rejects a long-form length with leading zero bytes" do
      expect_raises(ASN1::Error) { read_strict(Bytes[0x04, 0x82, 0x00, 0x01, 0x41]) }
    end

    it "accepts a minimal 2-octet long-form length (256)" do
      read_strict(Bytes[0x04, 0x82, 0x01, 0x00] + Bytes.new(256, 0x41_u8)).payload.size.should eq(256)
    end

    it "rejects an indefinite length" do
      expect_raises(ASN1::Error) { read_strict(Bytes[0x24, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00]) }
    end
  end

  describe "BOOLEAN" do
    it "accepts 00 and FF" do
      strict_ber(ASN1::BER::UniversalTags::Boolean, Bytes[0x00]).get_boolean.should be_false
      strict_ber(ASN1::BER::UniversalTags::Boolean, Bytes[0xFF]).get_boolean.should be_true
    end

    it "rejects a non-{00,FF} byte" do
      expect_raises(ASN1::Error) { strict_ber(ASN1::BER::UniversalTags::Boolean, Bytes[0x01]).get_boolean }
    end

    it "rejects a multi-byte BOOLEAN" do
      expect_raises(ASN1::Error) { strict_ber(ASN1::BER::UniversalTags::Boolean, Bytes[0xFF, 0xFF]).get_boolean }
    end
  end

  describe "INTEGER" do
    it "accepts a minimal encoding" do
      strict_ber(ASN1::BER::UniversalTags::Integer, Bytes[0x7F]).get_integer.should eq(127)
      strict_ber(ASN1::BER::UniversalTags::Integer, Bytes[0x00, 0x80]).get_integer.should eq(128)
    end

    it "rejects a redundant 0x00 pad" do
      # 00 7F is non-minimal (7F alone is already positive 127)
      expect_raises(ASN1::Error) { strict_ber(ASN1::BER::UniversalTags::Integer, Bytes[0x00, 0x7F]).get_integer }
    end

    it "rejects a redundant 0xFF pad" do
      # FF 80 is non-minimal (80 alone is already -128)
      expect_raises(ASN1::Error) { strict_ber(ASN1::BER::UniversalTags::Integer, Bytes[0xFF, 0x80]).get_integer }
    end

    it "rejects an empty INTEGER content" do
      expect_raises(ASN1::Error) { strict_ber(ASN1::BER::UniversalTags::Integer, Bytes.new(0)).get_integer }
    end
  end

  describe "OBJECT IDENTIFIER" do
    it "accepts a minimal OID" do
      # 1.2.840.113549 -> 2A 86 48 86 F7 0D
      strict_ber(ASN1::BER::UniversalTags::ObjectIdentifier,
        Bytes[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]).get_object_id.should eq("1.2.840.113549")
    end

    it "rejects a sub-identifier with a leading 0x80 (non-minimal)" do
      # 2A then 80 01 = a sub-id padded with a leading 0x80 continuation byte
      expect_raises(ASN1::Error) { strict_ber(ASN1::BER::UniversalTags::ObjectIdentifier, Bytes[0x2A, 0x80, 0x01]).get_object_id }
    end

    it "accepts a legitimate mid-sub-identifier 0x80" do
      # 2A 81 80 01 : second sub-id has a 0x80 as a *continuation* (not leading) byte
      strict_ber(ASN1::BER::UniversalTags::ObjectIdentifier, Bytes[0x2A, 0x81, 0x80, 0x01]).get_object_id
        .should eq("1.2.#{0x80 * 128 + 1}")
    end

    it "rejects an empty OBJECT IDENTIFIER" do
      expect_raises(ASN1::Error) { strict_ber(ASN1::BER::UniversalTags::ObjectIdentifier, Bytes.new(0)).get_object_id }
    end
  end

  describe "strings" do
    it "rejects an embedded NUL" do
      expect_raises(ASN1::Error) { strict_ber(ASN1::BER::UniversalTags::UTF8String, Bytes[0x41, 0x00, 0x42]).get_string }
    end

    it "accepts a NUL-free string" do
      strict_ber(ASN1::BER::UniversalTags::UTF8String, "hello".to_slice).get_string.should eq("hello")
    end
  end

  describe "SET OF ordering" do
    it "accepts children in canonical (ascending) order" do
      # SET { INTEGER 1, INTEGER 2 } -> 31 06 02 01 01 02 01 02
      read_strict(Bytes[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]).children.size.should eq(2)
    end

    it "rejects children out of order" do
      # SET { INTEGER 2, INTEGER 1 } -> not sorted
      expect_raises(ASN1::Error) { read_strict(Bytes[0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]).children }
    end

    it "does not enforce ordering on an implicitly context-tagged SET OF (documented limitation)" do
      # [0] IMPLICIT { INTEGER 2, INTEGER 1 } — a context tag is indistinguishable
      # from a SEQUENCE without a schema, so ordering isn't (and can't be) checked.
      read_strict(Bytes[0xA0, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]).children.size.should eq(2)
    end
  end

  it "propagates strict to children" do
    # SEQUENCE { <element with a non-minimal length> } — the child inherits strict
    frame = Bytes[0x30, 0x04, 0x04, 0x81, 0x01, 0x41]
    root = read_strict(frame)
    expect_raises(ASN1::Error) { root.children }
  end
end

# Not a strict-mode feature: the OID decoder builds a BigInt per sub-identifier,
# so an over-long continuation run is a CPU-amplification vector (super-linear
# multiply + decimal stringify). Bounded regardless of strict mode.
describe "ASN1::BER OID sub-identifier bound" do
  it "rejects an over-long sub-identifier" do
    ber = ASN1::BER.new
    ber.tag_number = ASN1::BER::UniversalTags::ObjectIdentifier
    # a single ~40-byte sub-identifier (well past any real arc, incl. a UUID)
    ber.payload = Bytes.new(40, 0x81_u8) + Bytes[0x01]
    expect_raises(ASN1::InvalidObjectId) { ber.get_object_id }
  end

  it "still decodes a UUID-sized arc (128-bit)" do
    # 2.25.<2^127> — a 128-bit second arc encodes in ~19 bytes, under the cap
    oid = "2.25.#{BigInt.new(2) ** 127}"
    ber = ASN1::BER.new
    ber.set_object_id(oid)
    ber.get_object_id.should eq(oid)
  end
end
