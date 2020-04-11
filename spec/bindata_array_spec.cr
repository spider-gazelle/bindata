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

  it "should read and write a variably sized array" do
    io = IO::Memory.new
    io.write_byte(5)
    io.write_byte(4)
    io.write_byte(3)
    io.write_byte(2)
    io.write_byte(1)
    io.rewind

    # Test read
    r = io.read_bytes(VariableArrayData)
    r.total_size.should eq(5)
    r.test.should eq([4_u8, 3_u8, 2_u8])
    r.afterdata.should eq(1)

    # test write
    io2 = IO::Memory.new
    r.write(io2)
    io2.to_slice.should eq(io.to_slice)
  end
end
