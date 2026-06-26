require "./helper"

# `get_integer` returns `Int64`. An INTEGER whose content does not fit `Int64`
# (more than 8 significant bytes) used to be decoded with `byte << (8 * index)`
# where the shift count reaches 64+, and `Int64 << 64 == 0` in Crystal — so a
# 9-byte `2^64` silently returned 0 and a 10-byte value returned -1. Reject it
# with a typed error instead of mis-decoding.
private def int_ber(payload : Bytes, tag = ASN1::BER::UniversalTags::Integer)
  ber = ASN1::BER.new
  ber.tag_number = tag
  ber.payload = payload
  ber
end

describe "ASN1::BER#get_integer Int64 bounds" do
  it "decodes the full 8-byte Int64::MAX" do
    int_ber(Bytes[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).get_integer.should eq(Int64::MAX)
  end

  it "decodes the full 8-byte Int64::MIN" do
    int_ber(Bytes[0x80, 0, 0, 0, 0, 0, 0, 0]).get_integer.should eq(Int64::MIN)
  end

  it "raises InvalidPayload on a 9-byte INTEGER that overflows Int64" do
    # 0x01 followed by 8 zero bytes == 2^64, unrepresentable in Int64
    expect_raises(ASN1::InvalidPayload) { int_ber(Bytes[0x01, 0, 0, 0, 0, 0, 0, 0, 0]).get_integer }
  end

  it "raises InvalidPayload on a 10-byte INTEGER" do
    expect_raises(ASN1::InvalidPayload) do
      int_ber(Bytes[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).get_integer
    end
  end

  it "round-trips representative values through set_integer/get_integer" do
    [0_i64, 1_i64, -1_i64, 127_i64, 128_i64, 255_i64, 256_i64, -128_i64, -129_i64,
     32767_i64, -32768_i64, 1234567890123_i64, -1234567890123_i64, Int64::MAX, Int64::MIN].each do |n|
      ber = ASN1::BER.new
      ber.set_integer(n)
      io = IO::Memory.new
      ber.write(io)
      io.rewind
      io.read_bytes(ASN1::BER).get_integer.should eq(n)
    end
  end

  it "decodes an Enumerated payload as an integer" do
    int_ber(Bytes[0x05], ASN1::BER::UniversalTags::Enumerated).get_integer.should eq(5_i64)
  end

  it "rejects on read a value written from an unsigned integer that overflows Int64" do
    # set_integer encodes UInt64::MAX as a valid 9-byte unsigned INTEGER, which
    # cannot be represented in the Int64 get_integer returns — read must reject,
    # not silently corrupt. Locks in write-side/read-side consistency.
    ber = ASN1::BER.new
    ber.set_integer(UInt64::MAX)
    expect_raises(ASN1::InvalidPayload) { ber.get_integer }
  end
end
