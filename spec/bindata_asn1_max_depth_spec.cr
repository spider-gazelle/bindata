require "./helper"

# Second-pass audit P-SEC (medium) — `max_content_length` caps bytes, not
# nesting depth. A few KB of `30 80 30 80 …` encodes thousands of levels, and a
# consumer that walks `children` recursively blows its stack (unrescuable in
# Crystal). A propagated `max_depth` (default 100) makes `children` raise a typed
# `ASN1::MaxDepthExceeded` once the nesting limit is reached.

# Builds `levels` nested definite-length SEQUENCEs wrapping an INTEGER 0.
# Kept shallow so every length stays in short form (< 128).
private def nested_seq(levels : Int32) : Bytes
  data = Bytes[0x02, 0x01, 0x00] # INTEGER 0
  levels.times do
    inner = data
    data = Bytes.new(inner.size + 2)
    data[0] = 0x30_u8 # constructed SEQUENCE
    data[1] = inner.size.to_u8
    inner.each_with_index { |b, i| data[i + 2] = b }
  end
  data
end

# Fully descends the constructed tree, forcing a `children` call at every level.
private def walk(ber : ASN1::BER) : Nil
  return unless ber.constructed
  ber.children.each { |child| walk(child) }
end

describe "ASN1::BER max_depth" do
  it "defaults to 100" do
    ASN1::BER.new.max_depth.should eq(100)
  end

  it "walks a tree within the depth limit" do
    ber = IO::Memory.new(nested_seq(4)).read_bytes(ASN1::BER)
    ber.max_depth = 4
    walk(ber) # 4 SEQUENCE levels -> deepest children() is on depth 3, allowed
  end

  it "raises once the nesting exceeds the limit" do
    ber = IO::Memory.new(nested_seq(4)).read_bytes(ASN1::BER)
    ber.max_depth = 3
    expect_raises(ASN1::MaxDepthExceeded) { walk(ber) }
  end

  it "treats 0 as unlimited" do
    ber = IO::Memory.new(nested_seq(6)).read_bytes(ASN1::BER)
    ber.max_depth = 0
    walk(ber) # no limit -> no raise
  end

  it "pins the exact boundary (N descents allowed)" do
    # SEQUENCE { SEQUENCE { INTEGER } }: walking calls children() at depth 0 then 1.
    two = nested_seq(2)

    # max_depth = 1 allows the descent at depth 0 but raises at depth 1.
    one = IO::Memory.new(two).read_bytes(ASN1::BER)
    one.max_depth = 1
    expect_raises(ASN1::MaxDepthExceeded) { walk(one) }

    # max_depth = 2 allows both descents (the leaf INTEGER is primitive).
    ok = IO::Memory.new(two).read_bytes(ASN1::BER)
    ok.max_depth = 2
    walk(ok)
  end

  it "propagates the limit onto each child" do
    ber = IO::Memory.new(nested_seq(2)).read_bytes(ASN1::BER)
    ber.max_depth = 7
    ber.children.first.max_depth.should eq(7)
  end
end
