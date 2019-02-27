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

class Body < BinData
  endian big

  uint8 :start, value: ->{ 0_u8 }

  bit_field do
    bits 6, :six, value: ->{ 0b1110_11_u8 }
    bits 3, :three, value: ->{ 0b011_u8 }
    bits 4, :four, value: ->{ 0b1001_u8 }
    bits 11, :teen, value: ->{ 0b1101_1111_101_u16 }
  end

  uint8 :mid, value: ->{ 0_u8 }

  bit_field do
    bits 52, :five, value: ->{ 0xF0_E0_D0_C0_B0_A0_9_u64 }
    bits 12, :eight, value: ->{ 0x104_u16 }
  end

  uint8 :end, value: ->{ 0_u8 }
end

describe BinData::BitField do
  it "should parse values out of dense binary structures" do
    io = IO::Memory.new
    # io.write_bytes(0b1110_1110_1000_0000_u16, IO::ByteFormat::BigEndian)
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

  it "should parse an object from an IO" do
    io = IO::Memory.new
    io.write_byte 0b0_u8
    io.write_byte 0b1110_1101_u8
    io.write_byte 0b1100_1110_u8
    io.write_byte 0b1111_1101_u8
    io.write_byte 0b0_u8
    io.write_bytes 0xF0_E0_D0_C0_B0_A0_91_04_u64, IO::ByteFormat::BigEndian
    io.write_byte 0b0_u8
    io.rewind

    r = Body.new
    r.read io
    r.start.should eq(0)
    r.six.should eq(0b1110_11)
    r.three.should eq(0b011)
    r.four.should eq(0b1001)
    r.teen.should eq(0b1101_1111_101)
    r.mid.should eq(0)
    r.five.should eq(0xF0_E0_D0_C0_B0_A0_9_u64)
    r.eight.should eq(0x104_u16)
    r.end.should eq(0)
  end

  it "should write an object to an IO" do
    io = IO::Memory.new
    io.write_byte 0b0_u8
    io.write_byte 0b1110_1101_u8
    io.write_byte 0b1100_1110_u8
    io.write_byte 0b1111_1101_u8
    io.write_byte 0b0_u8
    io.write_bytes 0xF0_E0_D0_C0_B0_A0_91_04_u64, IO::ByteFormat::BigEndian
    io.write_byte 0b0_u8
    io.rewind

    io2 = IO::Memory.new
    b = Body.new
    b.write(io2)
    io2.rewind

    io2.to_slice.should eq(io.to_slice)
  end
end
