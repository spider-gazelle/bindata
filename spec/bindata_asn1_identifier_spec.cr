require "./helper"

# Follow-up to the Tier 0.5 DoS work: `Identifier#read` looped appending
# `ExtendedIdentifier`s while the continuation bit was set, with no limit, so a
# stream of `more`-flagged bytes (0xFF...) grew the array unbounded. A fixed cap
# bounds it and raises a typed `InvalidTag`.
#
# Identifier byte 0x5F = tag_class Application, not constructed, tag_number 0b11111
# (=> extended? is true). Extended bytes: high bit = `more`, low 7 = tag number.

describe ASN1::BER::Identifier do
  it "rejects an over-long extended identifier" do
    bytes = Bytes[0x5F] + Bytes.new(20, 0xFF_u8) # 20 continuation bytes, never terminates
    io = IO::Memory.new(bytes)
    expect_raises(ASN1::InvalidTag) { io.read_bytes(ASN1::BER::Identifier) }
  end

  it "reads a valid multi-byte extended identifier" do
    io = IO::Memory.new(Bytes[0x5F, 0x81, 0x00]) # two extended bytes, second ends it
    id = io.read_bytes(ASN1::BER::Identifier)
    id.extended.size.should eq(2)
    id.tag_number.should eq(0b11111_u8)
  end

  it "accepts exactly the maximum number of extended bytes" do
    max = ASN1::BER::Identifier::MAX_EXTENDED_BYTES
    bytes = Bytes[0x5F] + Bytes.new(max - 1, 0x81_u8) + Bytes[0x00] # max parts, last terminates
    id = IO::Memory.new(bytes).read_bytes(ASN1::BER::Identifier)
    id.extended.size.should eq(max)
  end

  it "rejects one more than the maximum number of extended bytes" do
    max = ASN1::BER::Identifier::MAX_EXTENDED_BYTES
    bytes = Bytes[0x5F] + Bytes.new(max, 0x81_u8) + Bytes[0x00] # max + 1 parts
    io = IO::Memory.new(bytes)
    expect_raises(ASN1::InvalidTag) { io.read_bytes(ASN1::BER::Identifier) }
  end

  it "round-trips an extended identifier" do
    original = Bytes[0x5F, 0x81, 0x00]
    id = IO::Memory.new(original).read_bytes(ASN1::BER::Identifier)

    io = IO::Memory.new
    id.write(io)
    io.to_slice.should eq(original)
  end

  it "reads a plain (non-extended) identifier unchanged" do
    id = IO::Memory.new(Bytes[0x02]).read_bytes(ASN1::BER::Identifier)
    id.tag_class.should eq(ASN1::BER::TagClass::Universal)
    id.tag_number.should eq(2)
    id.extended.should be_empty
  end
end
