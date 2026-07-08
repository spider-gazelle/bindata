require "./helper"

# Second-pass audit P3 (non-breaking correctness on the BER facade):
#   - `#size` reported the stale decoded length, not the current payload size
#   - `#children` returned garbage when called on a primitive (non-constructed)

describe "ASN1::BER#size" do
  it "reflects the current payload size of an in-memory-built object" do
    ber = ASN1::BER.new
    ber.set_bytes(Bytes[1, 2, 3])
    # `@length.length` is only refreshed on write, so it was stale (0) here.
    ber.size.should eq(3)
  end

  it "matches the payload after a decode" do
    ber = IO::Memory.new(Bytes[0x04, 0x03, 1, 2, 3]).read_bytes(ASN1::BER)
    ber.size.should eq(3)
  end
end

describe "ASN1::BER#children" do
  it "raises on a primitive (non-constructed) element instead of parsing garbage" do
    ber = ASN1::BER.new
    # OctetString (primitive) whose payload merely looks like an inner TLV; the
    # old code would happily return that bogus child.
    ber.set_bytes(Bytes[0x02, 0x01, 0x05])
    ber.constructed.should be_false
    expect_raises(ASN1::Error) { ber.children }
  end

  it "still parses the children of a constructed element" do
    ber = IO::Memory.new(Bytes[0x30, 0x03, 0x02, 0x01, 0x05]).read_bytes(ASN1::BER)
    ber.constructed.should be_true
    children = ber.children
    children.size.should eq(1)
    children.first.tag.should eq(ASN1::BER::UniversalTags::Integer)
  end
end
