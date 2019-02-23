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

describe BinData::BitField do
  it "should parse values out of dense binary structures" do
    io = IO::Memory.new
    #io.write_bytes(0b1110_1110_1000_0000_u16, IO::ByteFormat::BigEndian)
    io.write_byte(0b1110_1110_u8)
    io.write_byte(0b1000_0000_u8)
    io.write_bytes(0_u16)
    io.write "hello".to_slice
    io.rewind

    bf = BinData::BitField.new
    bf.bits 7, :seven
    bf.bits 2, :two
    bf.bits 23, :three
    bf.apply

    bf.read(io, IO::ByteFormat::LittleEndian)
    bf[:seven].should eq(0b1110111)
    bf[:two].should eq(0b01)
    bf[:three].should eq(0)
  end
end
