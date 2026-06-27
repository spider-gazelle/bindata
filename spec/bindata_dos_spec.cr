require "./helper"

# P-SEC #1 / #5 — the generic DSL trusts an attacker-controlled `length:` before
# allocating, so a tiny hostile message can force a huge `Bytes`/`Array`
# allocation (verified ~50 MB from a single wire byte), and a non-advancing
# `variable_array` element loops forever. An opt-in per-instance
# `max_content_length` cap (default `0` = unlimited, so existing behaviour is
# unchanged) guards every generic allocation site and propagates into nested
# `BinData` children so a small frame cannot smuggle an oversized one.

private class GreedyBytes < BinData
  endian big
  field len : UInt32
  field payload : Bytes, length: -> { len.to_i }
end

private class GreedyString < BinData
  endian big
  field len : UInt32
  field text : String, length: -> { len.to_i }
end

private class CountedBytes < BinData
  endian big
  field count : UInt32
  field nums : Array(UInt8), length: -> { count.to_i }
end

private class Inner < BinData
  endian big
  field len : UInt32
  field payload : Bytes, length: -> { len.to_i }
end

private class NestedArray < BinData
  endian big
  field count : UInt32
  field items : Array(Inner), length: -> { count.to_i }
end

private class NestedBasic < BinData
  endian big
  field inner : Inner = Inner.new
end

private class WithGroup < BinData
  endian big
  group :g do
    field len : UInt32
    field payload : Bytes, length: -> { len.to_i }
  end
end

private class Empty < BinData
end

private class Loopy < BinData
  field items : Array(Empty), read_next: -> { true }
end

# variable_array of nested BinData: the cap must propagate into each element so
# an oversized inner field is rejected mid-stream.
private class VarNested < BinData
  endian big
  field items : Array(Inner), read_next: -> { true }
end

private def read_capped(klass : T.class, bytes : Bytes, cap : Int32) : T forall T
  obj = klass.new
  obj.max_content_length = cap
  obj.read(IO::Memory.new(bytes))
  obj
end

describe "BinData max_content_length" do
  it "defaults to 0 (unlimited), leaving existing behaviour unchanged" do
    GreedyBytes.new.max_content_length.should eq(0)

    obj = IO::Memory.new(Bytes[0, 0, 0, 3, 1, 2, 3]).read_bytes(GreedyBytes)
    obj.payload.should eq(Bytes[1, 2, 3])
  end

  it "reads a normal frame that fits within the cap" do
    obj = read_capped(GreedyBytes, Bytes[0, 0, 0, 3, 1, 2, 3], 1024)
    obj.payload.should eq(Bytes[1, 2, 3])
  end

  it "allows a length exactly equal to the cap (inclusive boundary)" do
    obj = read_capped(GreedyBytes, Bytes[0, 0, 0, 3, 1, 2, 3], 3)
    obj.payload.should eq(Bytes[1, 2, 3])
  end

  it "rejects an oversized Bytes length before allocating" do
    # len = 0x7FFFFFFF (~2 GiB), no payload actually follows.
    frame = Bytes[0x7F, 0xFF, 0xFF, 0xFF]
    expect_raises(BinData::ContentTooLarge) { read_capped(GreedyBytes, frame, 1024) }
  end

  it "rejects an oversized String length before allocating" do
    frame = Bytes[0x7F, 0xFF, 0xFF, 0xFF]
    expect_raises(BinData::ContentTooLarge) { read_capped(GreedyString, frame, 1024) }
  end

  it "rejects an oversized array element count before allocating" do
    # count = 0x7FFFFFFF; the cap fires before any per-element read.
    frame = Bytes[0x7F, 0xFF, 0xFF, 0xFF]
    expect_raises(BinData::ContentTooLarge) { read_capped(CountedBytes, frame, 1024) }
  end

  it "propagates the cap into nested BinData array elements (no smuggling)" do
    # count = 1, then an Inner announcing ~2 GiB. The outer frame is tiny.
    frame = Bytes[0, 0, 0, 1, 0x7F, 0xFF, 0xFF, 0xFF]
    expect_raises(BinData::ContentTooLarge) { read_capped(NestedArray, frame, 1024) }
  end

  it "propagates the cap into a nested BinData field" do
    frame = Bytes[0x7F, 0xFF, 0xFF, 0xFF]
    expect_raises(BinData::ContentTooLarge) { read_capped(NestedBasic, frame, 1024) }
  end

  it "propagates the cap into a group" do
    frame = Bytes[0x7F, 0xFF, 0xFF, 0xFF]
    expect_raises(BinData::ContentTooLarge) { read_capped(WithGroup, frame, 1024) }
  end

  it "propagates the cap into variable_array BinData elements" do
    # One Inner that fits, then a second announcing ~2 GiB; read_next stays true.
    frame = Bytes[0, 0, 0, 0, 0x7F, 0xFF, 0xFF, 0xFF]
    expect_raises(BinData::ContentTooLarge) { read_capped(VarNested, frame, 1024) }
  end

  it "never raises with no cap, even for a large declared length present on the wire" do
    # 4-byte length header (len = 4) + 4 payload bytes; the default cap of 0 must
    # leave this untouched.
    obj = IO::Memory.new(Bytes[0, 0, 0, 4, 9, 9, 9, 9]).read_bytes(GreedyBytes)
    obj.payload.should eq(Bytes[9, 9, 9, 9])
    obj.max_content_length.should eq(0)
  end

  it "bounds a non-advancing variable_array under a cap" do
    # `read_next` is always true and `Empty` consumes no bytes: without a cap
    # this loops forever. The cap turns it into a bounded failure.
    expect_raises(BinData::ContentTooLarge) { read_capped(Loopy, Bytes.new(0), 100) }
  end
end
