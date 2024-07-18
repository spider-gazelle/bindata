require "./helper"

class StrEncodingTest < BinData
  endian little

  field str : String, encoding: "GB2312", length: ->{ 2 }
end

describe "string encoding" do
  it "should serialize" do
    obj = StrEncodingTest.new
    obj.str = "好"
    obj.to_slice.should eq Bytes[186, 195]
    obj.str.to_slice.should eq Bytes[229, 165, 189]
  end

  it "should deserialize" do
    io = IO::Memory.new(Bytes[186, 195])
    obj = io.read_bytes(StrEncodingTest)
    obj.str.should eq "好"
  end
end
