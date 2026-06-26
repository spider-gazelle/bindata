require "./helper"

# Audit Tier 3 — ASN.1 BER length encoding/decoding correctness.
#  * a length of 127 fits in short form (0x7f) but was encoded in long form;
#  * a long-form length that overflows Int32 became silently negative.

describe ASN1::BER::Length do
  it "encodes length boundaries in minimal form" do
    {
             126 => Bytes[0x7e],
             127 => Bytes[0x7f],                         # short form, not 0x81 0x7f
             128 => Bytes[0x81, 0x80],                   # first value needing long form
             256 => Bytes[0x82, 0x01, 0x00],             # two long bytes
           65536 => Bytes[0x83, 0x01, 0x00, 0x00],       # three long bytes
      0x7FFFFFFF => Bytes[0x84, 0x7F, 0xFF, 0xFF, 0xFF], # max representable
    }.each do |len, goal|
      l = ASN1::BER::Length.new
      l.length = len

      io = IO::Memory.new
      l.write(io)
      io.to_slice.should eq(goal)

      io.rewind
      io.read_bytes(ASN1::BER::Length).length.should eq(len)
    end
  end

  it "reads the maximum representable long-form length" do
    io = IO::Memory.new(Bytes[0x84, 0x7F, 0xFF, 0xFF, 0xFF])
    io.read_bytes(ASN1::BER::Length).length.should eq(0x7FFFFFFF)
  end

  it "rejects a long-form length that exceeds Int32" do
    io = IO::Memory.new(Bytes[0x84, 0x80, 0x00, 0x00, 0x00])
    expect_raises(ASN1::BER::InvalidLength) { io.read_bytes(ASN1::BER::Length) }
  end
end
