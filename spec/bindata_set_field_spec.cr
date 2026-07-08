require "./helper"

# `field name : Set(T)` is advertised (README: "Arrays and Sets"), but the
# generated read code built an Array, so a Set field failed to compile. These
# specs lock in Set support for the fixed- and variable-length forms.

private class FixedSet < BinData
  endian big
  field n : UInt8
  field vals : Set(UInt8), length: -> { n }
end

private class VariableSet < BinData
  endian big
  field count : UInt8
  field vals : Set(UInt8), read_next: -> { vals.size < count }
end

describe "Set fields" do
  it "reads a fixed-length Set (de-duplicating repeats)" do
    obj = FixedSet.from_slice(Bytes[0x04, 0x01, 0x02, 0x02, 0x03])
    obj.vals.should eq(Set{0x01_u8, 0x02_u8, 0x03_u8})
  end

  it "reads a variable-length Set" do
    obj = VariableSet.from_slice(Bytes[0x03, 0x0A, 0x0B, 0x0C])
    obj.vals.should eq(Set{0x0A_u8, 0x0B_u8, 0x0C_u8})
  end

  it "writes the members of a Set" do
    obj = FixedSet.new
    obj.n = 3
    obj.vals = Set{0x01_u8, 0x02_u8, 0x03_u8}
    obj.to_slice.should eq(Bytes[0x03, 0x01, 0x02, 0x03])
  end
end
