require "./helper"

describe BinData do
  it "should parse an object with an array from an IO" do
    io = IO::Memory.new
    io.write_byte(2)
    io.write_bytes 0x0F09_i16, IO::ByteFormat::BigEndian
    io.write_bytes 0x0F09_i16, IO::ByteFormat::BigEndian
    io.write_byte(0)
    io.rewind

    r = io.read_bytes(ArrayData)
    r.flen.should eq(2_u8)
    r.first.should eq([0x0F09_u16, 0x0F09_u16])
    r.slen.should eq(0_u8)
    r.second.should eq([] of Int8)
  end

  it "should write an object with an array to an IO" do
    io = IO::Memory.new
    io.write_byte(2)
    io.write_bytes 0x0F09_i16, IO::ByteFormat::BigEndian
    io.write_bytes 0x0F09_i16, IO::ByteFormat::BigEndian
    io.write_byte(0)
    io.rewind

    r = ArrayData.new
    r.first = [0x0F09_i16, 0x0F09_i16]
    io2 = IO::Memory.new
    r.write(io2)
    io2.rewind
    io2.to_slice.should eq(io.to_slice)
  end
end
