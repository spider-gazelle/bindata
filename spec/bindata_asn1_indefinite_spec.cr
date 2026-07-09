require "./helper"

# Indefinite-length BER: the content is a sequence of complete TLV elements
# terminated by an end-of-contents `00 00`. The reader walks those elements (so a
# `00 00` *inside* a nested element no longer truncates the outer value — P0#4),
# and an indefinite element re-encodes to the same bytes (P0#7). Malformed,
# non-TLV content is rejected (strict; maintainer's call on #44).
describe "ASN1::BER indefinite-length content" do
  it "reads the exact content of an indefinite-length element" do
    # 0x24 constructed OctetString, 0x80 indefinite, inner TLV 04 03 'A' 'B' 'C', 00 00
    io = IO::Memory.new(Bytes[0x24, 0x80, 0x04, 0x03, 0x41, 0x42, 0x43, 0x00, 0x00])
    ber = io.read_bytes(ASN1::BER)
    ber.payload.should eq(Bytes[0x04, 0x03, 0x41, 0x42, 0x43])
  end

  it "reads an empty indefinite-length payload" do
    io = IO::Memory.new(Bytes[0x24, 0x80, 0x00, 0x00])
    io.read_bytes(ASN1::BER).payload.empty?.should be_true
  end

  it "rejects malformed, non-TLV indefinite content" do
    # 00 05 announces a 5-byte element with no body — not a valid TLV element.
    io = IO::Memory.new(Bytes[0x24, 0x80, 0x00, 0x05, 0x00, 0x00])
    ex = expect_raises(ASN1::Error) { io.read_bytes(ASN1::BER) }
    ex.cause.should_not be_nil # the underlying error is preserved
  end

  it "does not truncate on a 00 00 inside a nested element (P0#4)" do
    # inner OCTET STRING 04 02 00 00 (payload is two zero bytes), then the real EOC
    io = IO::Memory.new(Bytes[0x24, 0x80, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00])
    ber = io.read_bytes(ASN1::BER)
    ber.payload.should eq(Bytes[0x04, 0x02, 0x00, 0x00])
    child = ber.children.first
    child.tag.should eq(ASN1::BER::UniversalTags::OctetString)
    child.payload.should eq(Bytes[0x00, 0x00])
  end

  it "reads a nested indefinite element" do
    # outer indefinite -> inner indefinite OCTET STRING { 04 01 41 } 00 00, 00 00
    io = IO::Memory.new(Bytes[0x24, 0x80, 0x24, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00, 0x00, 0x00])
    inner = io.read_bytes(ASN1::BER).children.first
    inner.constructed.should be_true
    leaf = inner.children.first
    leaf.tag.should eq(ASN1::BER::UniversalTags::OctetString)
    String.new(leaf.payload).should eq("A")
  end

  it "round-trips an indefinite element to the same bytes (P0#7)" do
    original = Bytes[0x24, 0x80, 0x04, 0x03, 0x41, 0x42, 0x43, 0x00, 0x00]
    ber = IO::Memory.new(original).read_bytes(ASN1::BER)
    ber.to_slice.should eq(original)
  end

  it "round-trips a nested indefinite element" do
    original = Bytes[0x24, 0x80, 0x24, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00, 0x00, 0x00]
    ber = IO::Memory.new(original).read_bytes(ASN1::BER)
    ber.to_slice.should eq(original)
  end

  it "round-trips children through an indefinite-length frame" do
    io = IO::Memory.new(Bytes[0x24, 0x80, 0x04, 0x03, 0x41, 0x42, 0x43, 0x00, 0x00])
    ber = io.read_bytes(ASN1::BER)
    child = ber.children.first
    child.tag.should eq(ASN1::BER::UniversalTags::OctetString)
    String.new(child.payload).should eq("ABC")
  end

  it "recognises an end-of-contents element via #eoc?" do
    IO::Memory.new(Bytes[0x00, 0x00]).read_bytes(ASN1::BER).eoc?.should be_true
    IO::Memory.new(Bytes[0x04, 0x01, 0x41]).read_bytes(ASN1::BER).eoc?.should be_false
  end
end
