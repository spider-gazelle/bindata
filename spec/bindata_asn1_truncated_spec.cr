require "./helper"

# Audit Tier 1.2 — a truncated indefinite-length element used to surface as a raw
# NilAssertionError (`io.read_byte.not_nil!` at EOF) instead of a typed ASN.1 error.

describe "ASN1::BER truncated input" do
  it "raises a typed error on truncated indefinite-length content" do
    # 0x24 constructed, 0x80 indefinite length, content with no `00 00` terminator
    io = IO::Memory.new(Bytes[0x24, 0x80, 0x01, 0x02])
    expect_raises(ASN1::Error) { io.read_bytes(ASN1::BER) }
  end
end
