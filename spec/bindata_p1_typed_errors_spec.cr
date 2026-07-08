require "./helper"

# Second-pass audit P1 — untyped exceptions escaping the ASN1::Error /
# BinData::CustomException hierarchies. Grouped fixes:
#   1  Identifier#read on a truncated extended tag leaked IO::EOFError
#   4  callback failures raised a generic RuntimeError (now BinData::CallbackError)
#   7  BitField#bits accepted size <= 0
#   8  set_bytes/set_string aliased the caller's buffer / a read-only slice

# --- P1#4 ----------------------------------------------------------------------

private class BadDeserialize < BinData
  field x : UInt8
  after_deserialize do
    raise "boom in after_deserialize"
  end
end

private class BadSerialize < BinData
  field x : UInt8
  before_serialize do
    raise "boom in before_serialize"
  end
end

describe "P1#1 — truncated extended identifier" do
  it "raises a typed error instead of leaking IO::EOFError" do
    # 0x5F = Application class, tag_number 0b11111 (extended). 0x81 sets the
    # `more` bit, then the stream ends mid-continuation.
    io = IO::Memory.new(Bytes[0x5F, 0x81])
    expect_raises(ASN1::InvalidTag) { io.read_bytes(ASN1::BER::Identifier) }
  end

  it "surfaces the typed error as the cause through a full BER decode" do
    # Reading the identifier as a BER field wraps it in ParseError (the generic
    # field-read rescue), but the typed InvalidTag is preserved as the cause.
    io = IO::Memory.new(Bytes[0x5F, 0x81])
    ex = expect_raises(BinData::ParseError) { io.read_bytes(ASN1::BER) }
    ex.cause.should be_a(ASN1::InvalidTag)
  end
end

describe "P1#4 — callback failures" do
  it "wraps an after_deserialize failure in a typed CallbackError" do
    expect_raises(BinData::CallbackError) { BadDeserialize.from_slice(Bytes[1]) }
  end

  it "wraps a before_serialize failure in a typed CallbackError" do
    expect_raises(BinData::CallbackError) { BadSerialize.new.to_slice }
  end

  it "keeps the original error as the cause" do
    ex = expect_raises(BinData::CallbackError) { BadDeserialize.from_slice(Bytes[1]) }
    ex.cause.should be_a(Exception)
  end
end

describe "P1#7 — BitField#bits size validation" do
  it "rejects a zero-bit field" do
    expect_raises(ArgumentError) { BinData::BitField.new.bits(0, "z") }
  end

  it "rejects a negative-bit field" do
    expect_raises(ArgumentError) { BinData::BitField.new.bits(-1, "n") }
  end

  it "still rejects more than 128 bits" do
    expect_raises(ArgumentError) { BinData::BitField.new.bits(129, "big") }
  end

  it "accepts a valid width" do
    BinData::BitField.new.bits(8, "ok") # no raise
  end
end

describe "P1#8 — setter buffer ownership" do
  it "does not alias the caller's Bytes in set_bytes" do
    buf = Bytes[1, 2, 3]
    ber = ASN1::BER.new
    ber.set_bytes(buf)
    buf[0] = 9_u8
    ber.get_bytes.should eq(Bytes[1, 2, 3])
  end

  it "stores a mutable (non read-only) payload in set_string" do
    ber = ASN1::BER.new
    ber.set_string("AB")
    ber.payload[0] = 0x5A_u8 # a read-only string slice would raise here
    ber.payload.should eq(Bytes[0x5A, 0x42])
  end
end
