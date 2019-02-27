require "spec"
require "../src/bindata"

class Header < BinData
  endian little

  int32 :size, value: ->{ name.try &.bytesize || 0 }
  string :name, length: ->{ size }
end

describe BinData do
  it "should parse an object from an IO" do
    io = IO::Memory.new
    io.write_bytes 5
    io.write "hello".to_slice
    io.rewind

    r = Header.new
    r.read io
    r.size.should eq(5)
    r.name.should eq("hello")
  end

  it "should write an object to an IO" do
    io = IO::Memory.new
    io.write_bytes 8
    io.write "whatwhat".to_slice
    io.rewind

    r = Header.new
    r.name = "whatwhat"

    io2 = IO::Memory.new
    r.write(io2)
    io2.rewind

    io2.to_slice.should eq(io.to_slice)
  end
end
