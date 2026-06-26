require "./helper"

# Indefinite-length BER: the payload is everything up to the terminating 00 00.
# The reader uses one byte of look-ahead to avoid writing the terminator; it must
# not prepend a sentinel byte to the content (it used to seed the look-ahead with
# 0x01, which leaked into the payload).
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

  it "preserves a 0x00 content byte that is not part of the terminator" do
    # content is 00 05 (a lone 0x00 followed by a non-zero byte), then 00 00
    io = IO::Memory.new(Bytes[0x24, 0x80, 0x00, 0x05, 0x00, 0x00])
    io.read_bytes(ASN1::BER).payload.should eq(Bytes[0x00, 0x05])
  end

  it "round-trips children through an indefinite-length frame" do
    io = IO::Memory.new(Bytes[0x24, 0x80, 0x04, 0x03, 0x41, 0x42, 0x43, 0x00, 0x00])
    ber = io.read_bytes(ASN1::BER)
    child = ber.children.first
    child.tag.should eq(ASN1::BER::UniversalTags::OctetString)
    String.new(child.payload).should eq("ABC")
  end
end
