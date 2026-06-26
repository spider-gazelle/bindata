require "./helper"

# Audit Tier 0.5 — BER#read trusts the declared length before reading, so a tiny
# hostile message can force a ~2 GiB allocation or an unbounded read. An opt-in
# per-instance `max_content_length` cap guards every allocation site, and the cap
# propagates into `children` so a small frame cannot smuggle an oversized child.

private def read_capped(bytes : Bytes, cap : Int32) : ASN1::BER
  ber = ASN1::BER.new
  ber.max_content_length = cap
  ber.read(IO::Memory.new(bytes))
  ber
end

describe "ASN1::BER max_content_length" do
  it "defaults to 0 (unlimited), leaving existing behaviour unchanged" do
    ASN1::BER.new.max_content_length.should eq(0)

    # A normal frame read via the usual API is unaffected.
    ber = IO::Memory.new(Bytes[0x04, 0x03, 1, 2, 3]).read_bytes(ASN1::BER)
    ber.payload.should eq(Bytes[1, 2, 3])
  end

  it "rejects a definite length larger than the cap before allocating" do
    # OctetString, long-form length 0x7FFFFFFF (~2 GiB), no payload follows.
    header = Bytes[0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF]
    expect_raises(ASN1::BER::ContentTooLarge) { read_capped(header, 1024) }
  end

  it "bounds an indefinite-length value with no terminator" do
    # Indefinite length (0x80) followed by non-zero bytes that never reach 00 00.
    data = Bytes.new(64, 0x01_u8)
    data[0] = 0x24_u8 # constructed
    data[1] = 0x80_u8 # indefinite length
    expect_raises(ASN1::BER::ContentTooLarge) { read_capped(data, 16) }
  end

  it "propagates the cap into children (no amplification)" do
    # 8-byte SEQUENCE whose 6-byte payload nests a child announcing ~2 GiB.
    frame = Bytes[0x30, 0x06, 0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF]
    root = read_capped(frame, 1024) # the outer frame is small, so this succeeds
    expect_raises(ASN1::BER::ContentTooLarge) { root.children }
  end

  it "reads a normal frame that fits within the cap" do
    ber = read_capped(Bytes[0x04, 0x03, 1, 2, 3], 1024)
    ber.payload.should eq(Bytes[1, 2, 3])
  end

  it "allows a length exactly equal to the cap (inclusive boundary)" do
    ber = read_capped(Bytes[0x04, 0x03, 1, 2, 3], 3)
    ber.payload.should eq(Bytes[1, 2, 3])
  end

  it "accepts an empty payload" do
    read_capped(Bytes[0x04, 0x00], 1024).payload.should be_empty
  end

  it "propagates the cap to grandchildren" do
    # SEQUENCE { SEQUENCE { OCTET STRING announcing ~2 GiB } }
    frame = Bytes[0x30, 0x08, 0x30, 0x06, 0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF]
    child = read_capped(frame, 1024).children.first
    expect_raises(ASN1::BER::ContentTooLarge) { child.children }
  end
end
